# app.py
import os
from dotenv import load_dotenv

# Carrega variáveis do arquivo .env (se existir) para o ambiente
load_dotenv()

from flask import (Flask, render_template, request, redirect, url_for,
                   flash, session, abort)
from flask_sqlalchemy import SQLAlchemy
from flask_login import (LoginManager, UserMixin, login_user, logout_user,
                       login_required, current_user)
from flask_bcrypt import Bcrypt
from flask_wtf import FlaskForm
from flask_wtf.csrf import CSRFProtect
from wtforms import (StringField, PasswordField, SubmitField, SelectField,
                   SelectMultipleField, HiddenField, TextAreaField, widgets)
from wtforms.validators import DataRequired, Length, EqualTo, ValidationError, Email
from models import (db, User, Lawyer, Client, Process, Deadline, Document,
                    Notification, notification_read_status, acessor_lawyer_assignments) # Certifique-se que todos modelos estão importados
from datetime import date, datetime
from functools import wraps
# Import OperationalError para tratar erros de conexão com DB
from sqlalchemy.exc import IntegrityError, OperationalError
from sqlalchemy.orm import joinedload, aliased

# --- Configuração Inicial ---
app = Flask(__name__)

# --- Chave Secreta ---
# Essencial para segurança (sessões, CSRF)
app.config['SECRET_KEY'] = os.environ.get('FLASK_SECRET_KEY')
if not app.config['SECRET_KEY']:
    raise ValueError("A variável de ambiente FLASK_SECRET_KEY não foi definida! Crie um arquivo .env ou defina no seu ambiente.")
# --- Fim Chave Secreta ---


# --- Configuração do Banco de Dados (AWS RDS) ---
DATABASE_URL = os.environ.get('DATABASE_URL')
if not DATABASE_URL:
    # Em produção, é crucial que a DATABASE_URL esteja definida.
    raise ValueError("Variável de ambiente DATABASE_URL não definida! Configure-a no seu ambiente ou arquivo .env com a URI do AWS RDS.")

# Verifica se a URL é para PostgreSQL (ajuste se usar MySQL)
# Adicione verificações para outros tipos se necessário (mysql+pymysql://, etc.)
if not DATABASE_URL.startswith("postgresql://"):
     print(f"AVISO: DATABASE_URL não parece ser uma URI PostgreSQL Válida: {DATABASE_URL}")
     # Considere levantar um erro se só aceitar PostgreSQL
     # raise ValueError("DATABASE_URL deve ser uma URI PostgreSQL (começar com postgresql://)")

app.config['SQLALCHEMY_DATABASE_URI'] = DATABASE_URL
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
# Configurações recomendadas para SQLAlchemy com bancos de dados em nuvem/produção
app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
    "pool_pre_ping": True,   # Verifica a conexão antes de usá-la do pool
    "pool_recycle": 300,     # Recicla/Reconecta a cada 5 minutos (evita timeouts)
}
# --- Fim Configuração Banco ---


# --- Inicializa Extensões ---
# É importante inicializar após definir as configurações
db.init_app(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
csrf = CSRFProtect(app) # CSRFProtect deve ser inicializado após a SECRET_KEY ser definida
# --- Fim Inicializa Extensões ---


# Configurações do Flask-Login
login_manager.login_view = 'login'
login_manager.login_message_category = 'info'
login_manager.login_message = "Por favor, faça login para acessar esta página."

# --- Configuração do Flask-Login ---
@login_manager.user_loader
def load_user(user_id):
    """Carrega o usuário dado o ID armazenado na sessão."""
    return db.session.get(User, int(user_id))

# --- Decoradores de Permissão ---
def gestor_required(f):
    """Decorator para rotas que exigem papel 'gestor'."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_gestor:
            abort(403) # Forbidden
        return f(*args, **kwargs)
    return decorated_function

def advogado_required(f):
    """Decorator para rotas que exigem papel 'advogado' e vínculo a um perfil."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_advogado:
            abort(403) # Forbidden
        if not current_user.lawyer_profile_id:
            flash("Seu usuário advogado não está vinculado a um perfil. Contate o gestor.", "warning")
            logout_user()
            session.clear()
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def acessor_required(f):
    """
    Decorator para rotas que exigem papel 'acessor'.
    Verifica se está associado a advogados e se um advogado foi selecionado.
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_acessor:
            abort(403) # Forbidden

        assisted_query = current_user.lawyers_assisted
        if not assisted_query.first():
            flash("Seu usuário acessor não está associado a nenhum advogado. Contate o gestor.", "warning")
            logout_user()
            session.clear()
            return redirect(url_for('login'))

        selected_lawyer_id = session.get('selected_lawyer_id')

        if not selected_lawyer_id:
            assisted_lawyers = assisted_query.all()
            if len(assisted_lawyers) == 1:
                lawyer = assisted_lawyers[0]
                session['selected_lawyer_id'] = lawyer.id
                session['selected_lawyer_name'] = lawyer.name
            else:
                flash("Por favor, selecione um advogado para continuar.", "info")
                return redirect(url_for('select_lawyer_for_acessor'))
        else:
            if not assisted_query.filter_by(id=selected_lawyer_id).first():
                 session.pop('selected_lawyer_id', None)
                 session.pop('selected_lawyer_name', None)
                 flash("Seleção de advogado inválida ou removida. Por favor, selecione novamente.", "warning")
                 return redirect(url_for('select_lawyer_for_acessor'))

        return f(*args, **kwargs)
    return decorated_function

# --- Formulários WTForms ---
class RegistrationForm(FlaskForm):
    username = StringField('Usuário', validators=[DataRequired("Campo obrigatório."), Length(min=4, max=25, message="Deve ter entre 4 e 25 caracteres.")])
    email = StringField('Email', validators=[DataRequired("Campo obrigatório."), Email(message="Email inválido.")])
    password = PasswordField('Senha', validators=[DataRequired("Campo obrigatório."), Length(min=6, message='Mínimo 6 caracteres.')])
    confirm_password = PasswordField('Confirmar Senha', validators=[DataRequired("Campo obrigatório."), EqualTo('password', message='As senhas devem ser iguais.')])
    submit = SubmitField('Solicitar Cadastro')
    def validate_username(self, username):
        user = User.query.filter(User.username.ilike(username.data)).first()
        if user: raise ValidationError('Este nome de usuário já está em uso.')
    def validate_email(self, email):
        user = User.query.filter(User.email.ilike(email.data)).first()
        if user: raise ValidationError('Este email já está cadastrado.')

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired("Campo obrigatório."), Email(message="Email inválido.")])
    password = PasswordField('Senha', validators=[DataRequired("Campo obrigatório.")])
    submit = SubmitField('Login')

class EditUserForm(FlaskForm):
    role = SelectField('Papel', choices=[('advogado', 'Advogado'), ('acessor', 'Acessor')], validators=[DataRequired()])
    is_approved = SelectField('Aprovado', choices=[(1, 'Sim'), (0, 'Não')], coerce=int, validators=[DataRequired()])
    submit = SubmitField('Salvar Alterações')

class AssignLawyersToAcessorForm(FlaskForm):
    lawyers = SelectMultipleField('Advogados para Assistir', coerce=int, widget=widgets.ListWidget(prefix_label=False), option_widget=widgets.CheckboxInput())
    submit = SubmitField('Salvar Associações')

class LawyerForm(FlaskForm):
    name = StringField('Nome do Advogado/Escritório', validators=[DataRequired("Campo obrigatório."), Length(min=3, max=100)])
    submit = SubmitField('Salvar Perfil')
    def validate_name(self, name):
        lawyer_id_editing = None
        if request and request.endpoint == 'edit_lawyer_profile' and request.view_args:
            lawyer_id_editing = request.view_args.get('lawyer_id')
        query = Lawyer.query.filter(Lawyer.name.ilike(name.data))
        if lawyer_id_editing:
            try:
                lawyer_id_int = int(lawyer_id_editing)
                query = query.filter(Lawyer.id != lawyer_id_int)
            except (ValueError, TypeError): pass
        if query.first(): raise ValidationError('Já existe um perfil de advogado/escritório com este nome.')

class LinkUserToLawyerForm(FlaskForm):
    user_id = SelectField('Usuário (Advogado não vinculado)', coerce=int, validators=[DataRequired(message="Selecione um usuário.")])
    submit = SubmitField('Vincular Usuário ao Perfil')

class ChangePasswordForm(FlaskForm):
    current_password = PasswordField('Senha Atual', validators=[DataRequired("Campo obrigatório.")])
    new_password = PasswordField('Nova Senha', validators=[DataRequired("Campo obrigatório."), Length(min=6, message='Mínimo 6 caracteres.')])
    confirm_new_password = PasswordField('Confirmar Nova Senha', validators=[DataRequired("Campo obrigatório."), EqualTo('new_password', message='As novas senhas não coincidem.')])
    submit = SubmitField('Alterar Senha')

class NotificationForm(FlaskForm):
    message = TextAreaField('Mensagem da Notificação', validators=[DataRequired("Campo obrigatório."), Length(max=500, message="Máximo 500 caracteres.")])
    submit = SubmitField('Publicar Notificação')


# --- Criação do Banco de Dados e Usuário Gestor Inicial ---
# Este bloco será executado na inicialização da aplicação.
# Ele cria as tabelas se não existirem e o usuário gestor inicial (se necessário).
with app.app_context():
    try:
        # Tenta criar as tabelas (seguro executar mesmo se já existirem)
        db.create_all()
        print("Schema do banco de dados verificado/criado com sucesso.")

        # Verifica se JÁ EXISTE algum gestor no banco
        if not User.query.filter_by(role='gestor').first():
            print("Nenhum usuário GESTOR encontrado. Criando gestor inicial a partir de variáveis de ambiente...")

            # Busca as credenciais das variáveis de ambiente (definidas no .env ou no servidor)
            gestor_username = os.environ.get('INITIAL_GESTOR_USERNAME')
            gestor_email = os.environ.get('INITIAL_GESTOR_EMAIL')
            gestor_password = os.environ.get('INITIAL_GESTOR_PASSWORD')

            # Valida se as variáveis foram definidas
            if not all([gestor_username, gestor_email, gestor_password]):
                raise ValueError("Erro Crítico: Variáveis de ambiente INITIAL_GESTOR_USERNAME, INITIAL_GESTOR_EMAIL, e INITIAL_GESTOR_PASSWORD devem ser definidas para criar o gestor inicial.")

            # Validação simples do email
            if '@' not in gestor_email or '.' not in gestor_email.split('@')[1]:
                 raise ValueError("O INITIAL_GESTOR_EMAIL fornecido não parece ser um email válido.")

            # Cria o hash da senha
            hp = bcrypt.generate_password_hash(gestor_password).decode('utf-8')
            # Cria o usuário gestor com os dados do ambiente
            admin_user = User(username=gestor_username,
                              email=gestor_email.lower(), # Salva email em minúsculas
                              password_hash=hp,
                              role='gestor',
                              is_approved=True)
            db.session.add(admin_user)

            # Adiciona advogados de exemplo se não existirem (opcional)
            if not Lawyer.query.filter_by(name='Dr. Exemplo Silva').first():
                 db.session.add(Lawyer(name='Dr. Exemplo Silva'))
            if not Lawyer.query.filter_by(name='Dra. Exemplo Souza').first():
                 db.session.add(Lawyer(name='Dra. Exemplo Souza'))

            # Salva o novo usuário e advogados no banco
            db.session.commit()
            print("-" * 40)
            print(f"Usuário GESTOR inicial '{gestor_username}' criado com sucesso.")
            print(f"Email: {gestor_email}")
            print("Senha definida via variável de ambiente.")
            print("Certifique-se de guardar estas credenciais em local seguro.")
            print("-" * 40)
        else:
            # Informa que o gestor já existe
            print("Usuário GESTOR já existe no banco de dados.")

    except OperationalError as e:
        # Erro específico de conexão com o banco
        print("\n" + "="*60)
        print("!!! ERRO DE CONEXÃO COM O BANCO DE DADOS !!!")
        print("Verifique:")
        print("1. Se a variável de ambiente DATABASE_URL está definida corretamente no .env ou no ambiente.")
        print(f"   (Valor atual começa com: {DATABASE_URL[:30]}...) " if DATABASE_URL else "   (Variável DATABASE_URL não definida!)")
        print("2. Se as credenciais (usuário, senha, host/endpoint, porta, nome do banco) na DATABASE_URL estão corretas.")
        print("3. Se a instância RDS está em execução e acessível (verifique Status no console AWS e Security Groups).")
        print("4. Se o driver do banco (psycopg2-binary) está instalado no ambiente Python.")
        print(f"Erro original: {e}")
        print("="*60 + "\n")
        # Considerar parar a aplicação aqui em caso de erro de conexão
        # raise e
    except Exception as e:
        # Outros erros durante a inicialização
        db.session.rollback()
        print(f"Erro durante a inicialização do banco de dados ou criação do gestor: {e}")
        # raise e # Pode ser útil propagar o erro em alguns casos
# --- Fim Criação DB ---


# --- Context Processors ---
@app.context_processor
def inject_today():
    return {'today': date.today()}

@app.context_processor
def inject_current_year():
    return {'current_year': datetime.now().year}

@app.context_processor
def inject_notifications():
    notifications_data = []
    unread_count = 0
    if current_user.is_authenticated and (current_user.is_gestor or current_user.is_acessor):
         try:
             read_ids_subquery = db.session.query(notification_read_status.c.notification_id).filter_by(user_id=current_user.id).subquery()
             unread_count = db.session.query(db.func.count(Notification.id)).filter(Notification.id.notin_(read_ids_subquery)).scalar() or 0
             if unread_count > 0:
                 query = (
                     Notification.query
                     .options(joinedload(Notification.creator_lawyer))
                     .filter(Notification.id.notin_(read_ids_subquery))
                     .order_by(Notification.created_at.desc())
                     .limit(5)
                 )
                 objects = query.all()
                 for n in objects:
                     notifications_data.append({
                         'id': n.id,
                         'message': n.message,
                         'created_at': n.created_at.isoformat() if n.created_at else None,
                         'creator_name': n.creator_lawyer.name if n.creator_lawyer else "Sistema"
                     })
         except Exception as e:
             app.logger.error(f"Erro ao carregar notificações no context processor: {e}")
             notifications_data = []
             unread_count = 0
    return {'recent_unread_notifications_data': notifications_data, 'unread_notification_count': unread_count}

# --- Helper para exibir erros de formulário ---
def flash_form_errors(form, entity_name="Formulário"):
     for field, errors in form.errors.items():
         if field == 'csrf_token': continue
         try: label = getattr(form, field).label.text
         except AttributeError: label = field.replace('_',' ').title()
         for error in errors: flash(f"Erro em '{label}': {error}", 'danger')


# --- Rotas de Autenticação ---
@app.route("/register", methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated: return redirect(url_for('home'))
    form = RegistrationForm()
    if form.validate_on_submit():
        try:
            hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
            user = User(username=form.username.data, email=form.email.data.lower(), password_hash=hashed_password, role='advogado', is_approved=False)
            db.session.add(user)
            db.session.commit()
            flash('Solicitação de cadastro enviada com sucesso! Aguarde a aprovação de um gestor.', 'success')
            return redirect(url_for('login'))
        except IntegrityError:
            db.session.rollback()
            flash('Erro: Nome de usuário ou email já cadastrado. Tente novamente.', 'danger')
        except Exception as e:
            db.session.rollback()
            app.logger.error(f"Erro inesperado no registro: {e}")
            flash(f'Erro inesperado ao salvar no banco de dados. Tente novamente mais tarde.', 'danger')
    elif form.is_submitted(): flash_form_errors(form)
    return render_template('register.html', title='Registrar', form=form)

@app.route("/login", methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated: return redirect(url_for('home'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter(User.email.ilike(form.email.data)).first()
        if user and bcrypt.check_password_hash(user.password_hash, form.password.data):
            if not user.is_approved:
                flash('Sua conta ainda não foi aprovada por um gestor.', 'warning')
                return redirect(url_for('login'))
            if user.is_advogado and not user.lawyer_profile_id:
                flash('Seu usuário advogado não está vinculado a um perfil. Contate o gestor.', 'warning')
                return redirect(url_for('login'))
            if user.is_acessor and not user.lawyers_assisted.first():
                 flash('Seu usuário acessor não está associado a nenhum advogado. Contate o gestor.', 'warning')
                 return redirect(url_for('login'))
            login_user(user)
            session.pop('selected_lawyer_id', None)
            session.pop('selected_lawyer_name', None)
            session.pop('lastShownNotificationId', None)
            flash('Login bem-sucedido!', 'success')
            next_page = request.args.get('next')
            if next_page and not next_page.startswith('/'): next_page = None # Basic Open Redirect check
            return redirect(next_page or url_for('home'))
        else:
            flash('Login falhou. Verifique seu email e senha.', 'danger')
    elif form.is_submitted(): flash_form_errors(form)
    return render_template('login.html', title='Login', form=form)

@app.route("/logout")
@login_required
def logout():
    logout_user()
    session.pop('selected_lawyer_id', None)
    session.pop('selected_lawyer_name', None)
    session.pop('lastShownNotificationId', None)
    flash('Você foi desconectado.', 'info')
    return redirect(url_for('login'))

@app.route('/change-password', methods=['GET', 'POST'])
@login_required
def change_password():
     form = ChangePasswordForm()
     if form.validate_on_submit():
         if bcrypt.check_password_hash(current_user.password_hash, form.current_password.data):
             try:
                 new_hashed_password = bcrypt.generate_password_hash(form.new_password.data).decode('utf-8')
                 current_user.password_hash = new_hashed_password
                 db.session.commit()
                 flash('Sua senha foi alterada com sucesso!', 'success')
                 return redirect(url_for('home'))
             except Exception as e:
                 db.session.rollback()
                 app.logger.error(f"Erro ao alterar senha do user {current_user.id}: {e}")
                 flash(f'Erro ao salvar a nova senha. Tente novamente.', 'danger')
         else:
             flash('Senha atual incorreta.', 'danger')
     elif form.is_submitted(): flash_form_errors(form)
     return render_template('change_password.html', title='Alterar Senha', form=form)


# --- Rota "Home" (Redirecionamento Principal) ---
@app.route('/')
@app.route('/home')
@login_required
def home():
    if current_user.is_gestor: return redirect(url_for('manage_lawyer_profiles'))
    elif current_user.is_advogado: return redirect(url_for('dashboard')) # Decorator @advogado_required cuida do vínculo
    elif current_user.is_acessor:
        assisted_lawyers = current_user.lawyers_assisted.all()
        if len(assisted_lawyers) == 1:
            lawyer = assisted_lawyers[0]
            session['selected_lawyer_id'] = lawyer.id
            session['selected_lawyer_name'] = lawyer.name
            return redirect(url_for('dashboard'))
        elif len(assisted_lawyers) > 1: return redirect(url_for('select_lawyer_for_acessor'))
        else: # Não associado
            flash("Acessor não associado a nenhum advogado.", "warning")
            logout_user(); session.clear(); return redirect(url_for('login'))
    else: # Papel inválido
        flash('Papel de usuário inválido.', 'danger')
        logout_user(); session.clear(); return redirect(url_for('login'))


# --- Rotas do GESTOR ---
@app.route('/admin/users', methods=['GET', 'POST'])
@login_required
@gestor_required
def manage_users():
     edit_form = EditUserForm()
     if request.method == 'POST' and edit_form.validate_on_submit():
         user_id_to_edit = request.form.get('user_id_to_edit')
         user_to_edit = None
         if user_id_to_edit:
             try: user_to_edit = db.session.get(User, int(user_id_to_edit))
             except ValueError: flash("ID de usuário inválido.", "danger"); return redirect(url_for('manage_users'))
         else: flash("ID do usuário a editar não fornecido.", "danger"); return redirect(url_for('manage_users'))

         if user_to_edit:
             if user_to_edit.is_gestor: flash("Não é permitido editar gestores.", "warning")
             else:
                 try:
                     original_role = user_to_edit.role; new_role = edit_form.role.data
                     user_to_edit.role = new_role; user_to_edit.is_approved = bool(edit_form.is_approved.data)
                     if original_role == 'advogado' and new_role != 'advogado': user_to_edit.lawyer_profile_id = None
                     if original_role == 'acessor' and new_role != 'acessor': user_to_edit.lawyers_assisted = []
                     db.session.commit()
                     flash(f"Usuário '{user_to_edit.username}' atualizado.", "success")
                 except Exception as e:
                     db.session.rollback(); app.logger.error(f"Erro ao editar usuário {user_id_to_edit}: {e}")
                     flash(f"Erro ao salvar alterações.", "danger")
         else: flash("Usuário a ser editado não encontrado.", "warning")
         return redirect(url_for('manage_users'))
     elif request.method == 'POST': # Falha na validação do POST
         user_id_failed = request.form.get('user_id_to_edit', 'desconhecido')
         flash(f"Erro de validação ao editar usuário ID {user_id_failed}.", "danger")
         flash_form_errors(edit_form)

     users = User.query.order_by(User.role.desc(), User.username).all()
     return render_template('admin/manage_users.html', users=users, form=edit_form, title="Gerenciar Usuários")

@app.route('/admin/user/approve/<int:user_id>', methods=['POST'])
@login_required
@gestor_required
def approve_user(user_id):
    user = db.session.get(User, user_id)
    if user and not user.is_gestor:
        user.is_approved = True
        try: db.session.commit(); flash(f"Usuário '{user.username}' aprovado.", "success")
        except Exception as e: db.session.rollback(); app.logger.error(f"Erro ao aprovar user {user_id}: {e}"); flash("Erro ao aprovar.", "danger")
    elif user and user.is_gestor: flash("Não é possível aprovar/desaprovar gestor.", "warning")
    else: flash("Usuário não encontrado.", "warning")
    return redirect(url_for('manage_users'))

@app.route('/admin/user/disapprove/<int:user_id>', methods=['POST'])
@login_required
@gestor_required
def disapprove_user(user_id):
    user = db.session.get(User, user_id)
    if user and not user.is_gestor:
        user.is_approved = False
        try: db.session.commit(); flash(f"Usuário '{user.username}' desaprovado.", "success")
        except Exception as e: db.session.rollback(); app.logger.error(f"Erro ao desaprovar user {user_id}: {e}"); flash("Erro ao desaprovar.", "danger")
    elif user and user.is_gestor: flash("Não é possível aprovar/desaprovar gestor.", "warning")
    else: flash("Usuário não encontrado.", "warning")
    return redirect(url_for('manage_users'))

@app.route('/admin/user/delete/<int:user_id>', methods=['POST'])
@login_required
@gestor_required
def delete_user(user_id):
    user_to_delete = db.session.get(User, user_id)
    if not user_to_delete: flash("Usuário não encontrado.", "danger"); return redirect(url_for('manage_users'))
    if user_to_delete.is_gestor: flash("Não é possível excluir gestor.", "warning"); return redirect(url_for('manage_users'))
    if user_to_delete.id == current_user.id: flash("Você não pode excluir sua própria conta.", "warning"); return redirect(url_for('manage_users'))
    try:
        username = user_to_delete.username; db.session.delete(user_to_delete); db.session.commit()
        flash(f"Usuário '{username}' excluído permanentemente.", "success")
    except Exception as e:
        db.session.rollback(); app.logger.error(f"Erro ao excluir usuário {user_id}: {e}"); flash("Erro ao excluir usuário.", "danger")
    return redirect(url_for('manage_users'))

@app.route('/admin/user/assignments/<int:user_id>', methods=['GET', 'POST'])
@login_required
@gestor_required
def manage_acessor_assignments(user_id):
     user = db.session.get(User, user_id)
     if not user or not user.is_acessor: flash("Usuário inválido ou não é um acessor.", "warning"); return redirect(url_for('manage_users'))
     form = AssignLawyersToAcessorForm(request.form)
     all_lawyers = Lawyer.query.order_by(Lawyer.name).all()
     form.lawyers.choices = [(lawyer.id, lawyer.name) for lawyer in all_lawyers]
     if form.validate_on_submit():
           selected_ids = set(form.lawyers.data)
           selected_lawyers = Lawyer.query.filter(Lawyer.id.in_(selected_ids)).all() if selected_ids else []
           try:
               user.lawyers_assisted = selected_lawyers; db.session.commit()
               flash(f"Associações de advogados para '{user.username}' salvas.", "success")
               return redirect(url_for('manage_users'))
           except Exception as e:
               db.session.rollback(); app.logger.error(f"Erro ao salvar associações acessor {user_id}: {e}"); flash("Erro ao salvar associações.", "danger")
     elif request.method == 'GET': form.lawyers.data = [lawyer.id for lawyer in user.lawyers_assisted]
     elif form.is_submitted(): flash("Erro de validação.", "danger"); flash_form_errors(form)
     return render_template('admin/manage_acessor_assignments.html', form=form, user=user, title=f"Associar Advogados - {user.username}")

@app.route('/admin/lawyers')
@login_required
@gestor_required
def manage_lawyer_profiles():
    lawyer_form = LawyerForm(); link_form = LinkUserToLawyerForm()
    unlinked_users = User.query.filter_by(role='advogado', is_approved=True, lawyer_profile_id=None).order_by(User.username).all()
    link_form.user_id.choices = [(0, '-- Selecione um Usuário --')] + [(u.id, u.username) for u in unlinked_users]
    lawyers = Lawyer.query.options(joinedload(Lawyer.user_account)).order_by(Lawyer.name).all()
    return render_template('admin/manage_lawyer_profiles.html', lawyers=lawyers, lawyer_form=lawyer_form, link_form=link_form, title="Gerenciar Perfis de Advogado")

@app.route('/admin/lawyer/add', methods=['POST'])
@login_required
@gestor_required
def add_lawyer_profile():
     form = LawyerForm(formdata=request.form)
     if form.validate_on_submit():
         new_lawyer = Lawyer(name=form.name.data); db.session.add(new_lawyer)
         try: db.session.commit(); flash(f'Perfil "{new_lawyer.name}" criado.', 'success')
         except IntegrityError: db.session.rollback(); flash('Erro: Já existe perfil com este nome.', 'danger')
         except Exception as e: db.session.rollback(); app.logger.error(f"Erro ao criar perfil advogado: {e}"); flash('Erro ao criar perfil.', 'danger')
     else: flash("Erro ao criar perfil.", "danger"); flash_form_errors(form)
     return redirect(url_for('manage_lawyer_profiles'))

@app.route('/admin/lawyer/edit/<int:lawyer_id>', methods=['POST'])
@login_required
@gestor_required
def edit_lawyer_profile(lawyer_id):
     lawyer = db.session.get(Lawyer, lawyer_id)
     if not lawyer: flash("Perfil não encontrado.", "danger"); return redirect(url_for('manage_lawyer_profiles'))
     form = LawyerForm(formdata=request.form)
     if form.validate(): # validate() e não validate_on_submit() aqui
         lawyer.name = form.name.data
         try:
             db.session.commit(); flash(f'Perfil "{lawyer.name}" atualizado.', 'success')
             if session.get('selected_lawyer_id') == lawyer_id: session['selected_lawyer_name'] = lawyer.name
         except IntegrityError: db.session.rollback(); flash('Erro: Já existe outro perfil com este nome.', 'danger')
         except Exception as e: db.session.rollback(); app.logger.error(f"Erro edit perfil adv {lawyer_id}: {e}"); flash("Erro ao atualizar perfil.", "danger")
     else: flash(f"Erro ao editar perfil '{lawyer.name}'.", "danger"); flash_form_errors(form)
     return redirect(url_for('manage_lawyer_profiles'))

@app.route('/admin/lawyer/delete/<int:lawyer_id>', methods=['POST'])
@login_required
@gestor_required
def delete_lawyer_profile(lawyer_id):
    lawyer = db.session.get(Lawyer, lawyer_id)
    if not lawyer: flash("Perfil não encontrado.", "danger"); return redirect(url_for('manage_lawyer_profiles'))
    if not lawyer.can_delete(): flash(f'Não é possível excluir "{lawyer.name}", possui vínculos.', 'danger'); return redirect(url_for('manage_lawyer_profiles'))
    try:
        name = lawyer.name; db.session.delete(lawyer); db.session.commit(); flash(f'Perfil "{name}" excluído.', 'success')
        if session.get('selected_lawyer_id') == lawyer_id:
             session.pop('selected_lawyer_id', None); session.pop('selected_lawyer_name', None); flash("Perfil visualizado foi excluído.", "info")
    except Exception as e: db.session.rollback(); app.logger.error(f"Erro ao excluir perfil adv {lawyer_id}: {e}"); flash("Erro ao excluir perfil.", "danger")
    return redirect(url_for('manage_lawyer_profiles'))

@app.route('/admin/lawyer/link/<int:lawyer_id>', methods=['POST'])
@login_required
@gestor_required
def link_user_to_lawyer(lawyer_id):
    lawyer = db.session.get(Lawyer, lawyer_id)
    if not lawyer: flash("Perfil não encontrado.", "danger"); return redirect(url_for('manage_lawyer_profiles'))
    if lawyer.user_account: flash(f"Perfil '{lawyer.name}' já vinculado a '{lawyer.user_account.username}'.", "warning"); return redirect(url_for('manage_lawyer_profiles'))
    form = LinkUserToLawyerForm(formdata=request.form)
    unlinked_users = User.query.filter_by(role='advogado', is_approved=True, lawyer_profile_id=None).order_by(User.username).all()
    form.user_id.choices = [(0, '-- Selecione um Usuário --')] + [(u.id, u.username) for u in unlinked_users]
    if form.validate_on_submit():
        user_id_to_link = form.user_id.data
        if user_id_to_link == 0: flash("Selecione um usuário.", "warning")
        else:
            user = db.session.get(User, user_id_to_link)
            if user and user.is_advogado and user.is_approved and not user.lawyer_profile_id:
                try: user.lawyer_profile_id = lawyer.id; db.session.commit(); flash(f"Usuário '{user.username}' vinculado a '{lawyer.name}'.", "success")
                except Exception as e: db.session.rollback(); app.logger.error(f"Erro ao vincular user {user_id_to_link} a lawyer {lawyer_id}: {e}"); flash("Erro ao vincular.", "danger")
            else: flash("Usuário selecionado inválido ou não pode ser vinculado.", "warning")
    else: flash("Erro ao vincular.", "danger"); flash_form_errors(form)
    return redirect(url_for('manage_lawyer_profiles'))

@app.route('/admin/lawyer/unlink/<int:lawyer_id>', methods=['POST'])
@login_required
@gestor_required
def unlink_user_from_lawyer(lawyer_id):
    lawyer = db.session.get(Lawyer, lawyer_id)
    if not lawyer or not lawyer.user_account: flash("Perfil não encontrado ou não vinculado.", "warning"); return redirect(url_for('manage_lawyer_profiles'))
    user = lawyer.user_account
    try: user.lawyer_profile_id = None; db.session.commit(); flash(f"Usuário '{user.username}' desvinculado de '{lawyer.name}'.", "success")
    except Exception as e: db.session.rollback(); app.logger.error(f"Erro ao desvincular user {user.id} do lawyer {lawyer_id}: {e}"); flash("Erro ao desvincular.", "danger")
    return redirect(url_for('manage_lawyer_profiles'))

@app.route('/admin/lawyer/select/<int:lawyer_id>', methods=['POST'])
@login_required
@gestor_required
def select_lawyer_profile_for_gestor(lawyer_id):
    lawyer = db.session.get(Lawyer, lawyer_id)
    if lawyer:
        session['selected_lawyer_id'] = lawyer.id; session['selected_lawyer_name'] = lawyer.name
        flash(f'Visualizando dados de: {lawyer.name}.', 'info')
        return redirect(url_for('dashboard'))
    else: flash('Perfil não encontrado.', 'warning'); return redirect(url_for('manage_lawyer_profiles'))


# --- Rota para Acessor Selecionar Advogado ---
@app.route('/acessor/select_lawyer', methods=['GET', 'POST'])
@login_required
def select_lawyer_for_acessor():
     if not current_user.is_acessor: abort(403)
     assisted_lawyers = current_user.lawyers_assisted.order_by(Lawyer.name).all()
     if not assisted_lawyers: flash("Você não está associado a nenhum advogado.", "warning"); return redirect(url_for('logout'))
     if request.method == 'POST':
          lawyer_id_str = request.form.get('lawyer_id')
          if lawyer_id_str:
             try:
                 lawyer_id_int = int(lawyer_id_str)
                 selected_lawyer = next((l for l in assisted_lawyers if l.id == lawyer_id_int), None)
                 if selected_lawyer:
                     session['selected_lawyer_id'] = selected_lawyer.id; session['selected_lawyer_name'] = selected_lawyer.name
                     session.pop('lastShownNotificationId', None); flash(f'Acessando dados de {selected_lawyer.name}.', 'info')
                     return redirect(url_for('dashboard'))
                 else: flash('Seleção inválida.', 'warning')
             except ValueError: flash('ID inválido.', 'danger')
          else: flash('Selecione um advogado.', 'warning')
     # CORREÇÃO APLICADA: Tenta carregar de 'acessor/' primeiro
     template_path = 'acessor/select_lawyer.html'
     try: return render_template(template_path, assisted_lawyers=assisted_lawyers, title="Selecionar Advogado")
     except Exception as e:
         app.logger.error(f"Erro ao renderizar {template_path}: {e}. Tentando fallback.")
         try: return render_template('select_lawyer.html', assisted_lawyers=assisted_lawyers, title="Selecionar Advogado")
         except Exception as fallback_e:
            app.logger.error(f"Erro ao renderizar fallback select_lawyer.html: {fallback_e}")
            flash("Erro ao carregar página de seleção.", "danger"); return redirect(url_for('logout'))


# --- Rotas Comuns (Dashboard, Clientes, Prazos, etc.) ---
def get_current_lawyer_context():
    if not current_user.is_authenticated: return None, None
    lawyer_id = None; lawyer_name = None
    if current_user.is_gestor:
        lawyer_id = session.get('selected_lawyer_id')
        if lawyer_id:
            lawyer = db.session.get(Lawyer, lawyer_id)
            if lawyer: lawyer_name = lawyer.name
            else: session.pop('selected_lawyer_id', None); session.pop('selected_lawyer_name', None); lawyer_id = None
    elif current_user.is_advogado:
        if current_user.lawyer_profile: lawyer_id = current_user.lawyer_profile_id; lawyer_name = current_user.lawyer_profile.name
    elif current_user.is_acessor:
        lawyer_id = session.get('selected_lawyer_id')
        if lawyer_id:
             if current_user.lawyers_assisted.filter_by(id=lawyer_id).first(): lawyer_name = session.get('selected_lawyer_name')
             else: session.pop('selected_lawyer_id', None); session.pop('selected_lawyer_name', None); lawyer_id = None
    return lawyer_id, lawyer_name

@app.route('/dashboard')
@login_required
def dashboard():
    lawyer_id, lawyer_name = get_current_lawyer_context()
    if not lawyer_id:
        if current_user.is_gestor: flash('Selecione um perfil para visualizar.', 'info'); return redirect(url_for('manage_lawyer_profiles'))
        elif current_user.is_acessor: flash('Selecione um advogado para visualizar.', 'info'); return redirect(url_for('select_lawyer_for_acessor'))
        else: flash('Contexto inválido.', 'warning'); return redirect(url_for('home'))
    notification_form = NotificationForm() if current_user.is_advogado else None
    try:
        client_count = db.session.query(db.func.count(Client.id)).filter_by(lawyer_id=lawyer_id).scalar()
        open_deadlines_count = db.session.query(db.func.count(Deadline.id)).join(Process).filter(Process.lawyer_id == lawyer_id, Deadline.status.in_(['open', 'extended'])).scalar()
    except Exception as e:
        app.logger.error(f"Erro contadores dashboard L-{lawyer_id}: {e}"); flash("Erro ao carregar dados.", "danger")
        client_count = 0; open_deadlines_count = 0
    return render_template('dashboard.html', lawyer_name=lawyer_name, notification_form=notification_form, client_count=client_count or 0, open_deadlines_count=open_deadlines_count or 0, title=f"Painel - {lawyer_name}")

@app.route('/clients/add', methods=['GET', 'POST'])
@login_required
def add_client():
    lawyer_id, lawyer_name = get_current_lawyer_context()
    if not lawyer_id: flash('Contexto inválido.', 'danger'); return redirect(url_for('home'))
    if request.method == 'POST':
        name = request.form.get('name'); cpf = request.form.get('cpf')
        if not name or not cpf: flash('Nome e CPF são obrigatórios.', 'warning'); return render_template('add_client.html', title="Cadastrar Cliente", form_data=request.form)
        if Client.query.filter_by(cpf=cpf, lawyer_id=lawyer_id).first(): flash(f'CPF {cpf} já cadastrado para {lawyer_name}.', 'danger'); return render_template('add_client.html', title="Cadastrar Cliente", form_data=request.form)
        new_client = Client(lawyer_id=lawyer_id, name=name, cpf=cpf, phone=request.form.get('phone'), email=request.form.get('email', '').lower(), address=request.form.get('address'), rg=request.form.get('rg'), profession=request.form.get('profession'), other_info=request.form.get('other_info'))
        db.session.add(new_client)
        try:
            db.session.commit(); flash(f'Cliente "{new_client.name}" cadastrado.', 'success')
            document_link = request.form.get('document_link')
            if document_link:
                try: initial_doc = Document(filename="Link Documentos Iniciais", storage_link=document_link, client_id=new_client.id); db.session.add(initial_doc); db.session.commit(); flash('Link inicial adicionado.', 'info')
                except Exception as doc_e: db.session.rollback(); app.logger.error(f"Erro doc inicial C-{new_client.id}: {doc_e}"); flash('Erro ao adicionar link.', 'warning')
            return redirect(url_for('client_list'))
        except Exception as e:
            db.session.rollback(); app.logger.error(f"Erro ao salvar cliente L-{lawyer_id}: {e}"); flash('Erro ao salvar cliente.', 'danger')
            return render_template('add_client.html', title="Cadastrar Cliente", form_data=request.form)
    return render_template('add_client.html', title="Cadastrar Cliente")

@app.route('/clients')
@login_required
def client_list():
    lawyer_id, lawyer_name = get_current_lawyer_context()
    if not lawyer_id: flash('Contexto inválido.', 'danger'); return redirect(url_for('home'))
    try: clients = Client.query.filter_by(lawyer_id=lawyer_id).order_by(Client.name).all()
    except Exception as e: app.logger.error(f"Erro lista clientes L-{lawyer_id}: {e}"); flash("Erro ao carregar clientes.", "danger"); clients = []
    return render_template('client_list.html', clients=clients, lawyer_name=lawyer_name, title=f"Clientes - {lawyer_name}")

@app.route('/client/<int:client_id>', methods=['GET', 'POST'])
@login_required
def client_detail(client_id):
    lawyer_id, lawyer_name = get_current_lawyer_context()
    if not lawyer_id: flash('Contexto inválido.', 'danger'); return redirect(url_for('home'))
    client = Client.query.filter_by(id=client_id, lawyer_id=lawyer_id).first()
    if not client: flash('Cliente não encontrado neste contexto.', 'danger'); return redirect(url_for('client_list'))

    if request.method == 'POST':
        action = request.form.get('action')
        redirect_hash = '#processos-pane' if 'process' in action or 'deadline' in action else '#documentos-pane' if 'document' in action else '#dados-pane'
        try:
            if action == 'update_client':
                 client.name = request.form.get('name', client.name); client.phone = request.form.get('phone', client.phone)
                 client.email = request.form.get('email', client.email).lower(); client.address = request.form.get('address', client.address)
                 client.profession = request.form.get('profession', client.profession); client.other_info = request.form.get('other_info', client.other_info)
                 db.session.commit(); flash('Dados atualizados.', 'success')
            elif action == 'add_document':
                 link = request.form.get('document_link'); filename = request.form.get('document_filename', 'Novo Link')
                 if link: new_doc = Document(filename=filename or "Link", storage_link=link, client_id=client_id); db.session.add(new_doc); db.session.commit(); flash('Link adicionado.', 'success')
                 else: flash('Link é obrigatório.', 'warning')
            elif action == 'add_process':
                 description = request.form.get('process_description'); case_number = request.form.get('case_number')
                 if description: new_process = Process(description=description, case_number=case_number or None, client_id=client_id, lawyer_id=lawyer_id, status='active'); db.session.add(new_process); db.session.commit(); flash('Processo incluído.', 'success')
                 else: flash('Descrição obrigatória.', 'warning')
            elif action == 'update_process':
                 process_id_str = request.form.get('process_id'); update_text = request.form.get('update_text')
                 if process_id_str and update_text:
                     try: process_id_int = int(process_id_str)
                     except ValueError: flash('ID processo inválido.', 'danger'); return redirect(url_for('client_detail', client_id=client_id) + redirect_hash)
                     process_to_update = Process.query.filter_by(id=process_id_int, client_id=client_id, lawyer_id=lawyer_id).first()
                     if process_to_update: now_str = datetime.now().strftime("%d/%m/%Y %H:%M"); new_update_entry = f"[{now_str}]: {update_text}"; process_to_update.updates = f"{new_update_entry}\n{process_to_update.updates or ''}"; db.session.commit(); flash('Andamento registrado.', 'success')
                     else: flash('Processo inválido.', 'danger')
                 elif not update_text: flash('Texto do andamento vazio.', 'warning')
                 else: flash('Erro ao identificar processo.', 'danger')
            elif action == 'add_deadline':
                 process_id_for_deadline_str = request.form.get('process_id_for_deadline'); deadline_description = request.form.get('deadline_description'); deadline_due_date_str = request.form.get('deadline_due_date')
                 if process_id_for_deadline_str and deadline_description and deadline_due_date_str:
                     try: process_id_int = int(process_id_for_deadline_str)
                     except ValueError: flash('ID processo inválido.', 'danger'); return redirect(url_for('client_detail', client_id=client_id) + redirect_hash)
                     process_for_deadline = Process.query.filter_by(id=process_id_int, client_id=client_id, lawyer_id=lawyer_id).first()
                     if process_for_deadline:
                         try: due_date_obj = datetime.strptime(deadline_due_date_str, '%Y-%m-%d').date()
                         except ValueError: flash('Data inválida (AAAA-MM-DD).', 'danger'); return redirect(url_for('client_detail', client_id=client_id) + redirect_hash)
                         new_deadline = Deadline(description=deadline_description, due_date=due_date_obj, process_id=process_id_int, status='open'); db.session.add(new_deadline); db.session.commit(); flash('Prazo adicionado.', 'success')
                     else: flash('Processo associado inválido.', 'danger')
                 else: flash('Todos os campos são obrigatórios para adicionar prazo.', 'warning')
            else: flash('Ação desconhecida.', 'danger')
        except Exception as e:
             db.session.rollback(); app.logger.error(f"Erro POST client_detail C-{client_id} A-{action}: {e}")
             flash('Erro ao processar solicitação.', 'danger')
        return redirect(url_for('client_detail', client_id=client_id) + redirect_hash)

    # GET request
    try:
        active_processes = Process.query.filter_by(client_id=client_id, lawyer_id=lawyer_id, status='active').order_by(Process.id.desc()).all()
        documents = Document.query.filter_by(client_id=client_id).order_by(Document.upload_date.desc()).all()
    except Exception as e: app.logger.error(f"Erro GET client_detail C-{client_id}: {e}"); flash("Erro ao carregar detalhes.", "danger"); active_processes = []; documents = []
    return render_template('client_detail.html', client=client, active_processes=active_processes, documents=documents, title=f"Detalhes - {client.name}")

@app.route('/client/delete/<int:client_id>', methods=['POST'])
@login_required
def delete_client(client_id):
    lawyer_id, _ = get_current_lawyer_context()
    if not lawyer_id: flash("Contexto inválido.", "danger"); return redirect(url_for('home'))
    client_to_delete = Client.query.filter_by(id=client_id, lawyer_id=lawyer_id).first()
    if not client_to_delete: flash("Cliente não encontrado.", "danger"); return redirect(url_for('client_list'))
    try: client_name = client_to_delete.name; db.session.delete(client_to_delete); db.session.commit(); flash(f"Cliente '{client_name}' excluído.", "success")
    except Exception as e: db.session.rollback(); app.logger.error(f"Erro ao excluir cliente {client_id} L-{lawyer_id}: {e}"); flash("Erro ao excluir.", "danger")
    return redirect(url_for('client_list'))

@app.route('/deadlines')
@login_required
def deadlines():
    lawyer_id, lawyer_name = get_current_lawyer_context()
    if not lawyer_id: flash('Contexto inválido.', 'danger'); return redirect(url_for('home'))
    try:
        deadlines_list = Deadline.query.join(Process).filter(Process.lawyer_id == lawyer_id, Deadline.status.in_(['open', 'extended'])).options(joinedload(Deadline.process).joinedload(Process.client)).order_by(Deadline.due_date.asc()).all()
    except Exception as e: app.logger.error(f"Erro ao buscar prazos L-{lawyer_id}: {e}"); flash("Erro ao carregar prazos.", "danger"); deadlines_list = []
    return render_template('deadlines.html', deadlines=deadlines_list, lawyer_name=lawyer_name, title=f"Prazos - {lawyer_name}")

@app.route('/deadline/complete/<int:deadline_id>', methods=['POST'])
@login_required
def complete_deadline(deadline_id):
    lawyer_id, _ = get_current_lawyer_context()
    deadline = None
    if lawyer_id: deadline = Deadline.query.join(Process).filter(Deadline.id == deadline_id, Process.lawyer_id == lawyer_id, Deadline.status.in_(['open', 'extended'])).first()
    if not deadline: flash("Prazo inválido.", "danger"); return redirect(request.referrer or url_for('deadlines'))
    try: deadline.status = 'completed'; db.session.commit(); flash(f'Prazo "{deadline.description}" concluído.', 'success')
    except Exception as e: db.session.rollback(); app.logger.error(f"Erro ao completar prazo {deadline_id} L-{lawyer_id}: {e}"); flash('Erro ao baixar prazo.', 'danger')
    return redirect(request.referrer or url_for('deadlines'))

@app.route('/deadline/extend/<int:deadline_id>', methods=['POST'])
@login_required
def extend_deadline(deadline_id):
    lawyer_id, _ = get_current_lawyer_context()
    deadline = None
    if lawyer_id: deadline = Deadline.query.join(Process).filter(Deadline.id == deadline_id, Process.lawyer_id == lawyer_id, Deadline.status.in_(['open', 'extended'])).first()
    if not deadline: flash("Prazo inválido.", "danger"); return redirect(request.referrer or url_for('deadlines'))
    new_due_date_str = request.form.get('new_due_date')
    if new_due_date_str:
        try:
            new_due_date_obj = datetime.strptime(new_due_date_str, '%Y-%m-%d').date()
            deadline.due_date = new_due_date_obj; deadline.status = 'extended'; db.session.commit()
            flash(f'Prazo "{deadline.description}" prorrogado para {new_due_date_obj.strftime("%d/%m/%Y")}.', 'success')
        except ValueError: flash('Data inválida (AAAA-MM-DD).', 'danger')
        except Exception as e: db.session.rollback(); app.logger.error(f"Erro ao prorrogar prazo {deadline_id} L-{lawyer_id}: {e}"); flash('Erro ao salvar prorrogação.', 'danger')
    else: flash('Nova data é obrigatória.', 'warning')
    return redirect(request.referrer or url_for('deadlines'))

@app.route('/archived')
@login_required
def archived_processes():
    lawyer_id, lawyer_name = get_current_lawyer_context()
    if not lawyer_id: flash('Contexto inválido.', 'danger'); return redirect(url_for('home'))
    try:
        # CORREÇÃO APLICADA: Join explícito
        archived_list = (
            db.session.query(Process)
            .join(Client, Process.client_id == Client.id)
            .filter(Process.lawyer_id == lawyer_id, Process.status == 'archived')
            .options(joinedload(Process.client))
            .order_by(Client.name.asc(), Process.id.desc())
            .all()
        )
    except Exception as e: app.logger.error(f"Erro ao buscar arquivados L-{lawyer_id}: {e}"); flash("Erro ao carregar arquivados.", "danger"); archived_list = []
    return render_template('archived_processes.html', processes=archived_list, lawyer_name=lawyer_name, title=f"Arquivados - {lawyer_name}")

@app.route('/process/archive/<int:process_id>', methods=['POST'])
@login_required
def archive_process(process_id):
    lawyer_id, _ = get_current_lawyer_context()
    process = None; redirect_url = url_for('client_list')
    if lawyer_id: process = Process.query.filter_by(id=process_id, lawyer_id=lawyer_id, status='active').first()
    if not process:
        flash("Processo inválido.", "danger")
        if request.referrer and '/client/' in request.referrer:
             try: client_id_fallback = int(request.referrer.split('/client/')[1].split('?')[0].split('#')[0]); redirect_url = url_for('client_detail', client_id=client_id_fallback) + '#processos-pane'
             except: pass
        return redirect(redirect_url)
    redirect_url = url_for('client_detail', client_id=process.client_id) + '#processos-pane'
    pending_deadlines_count = Deadline.query.filter(Deadline.process_id == process_id, Deadline.status.in_(['open', 'extended'])).count()
    if pending_deadlines_count > 0: flash(f'Não arquivado: {pending_deadlines_count} prazo(s) pendente(s).', 'warning')
    else:
         process.status = 'archived'
         try: db.session.commit(); flash(f'Processo #{process.id} arquivado.', 'success')
         except Exception as e: db.session.rollback(); app.logger.error(f"Erro ao arquivar P-{process_id} L-{lawyer_id}: {e}"); flash('Erro ao arquivar.', 'danger')
    return redirect(redirect_url)

@app.route('/process/reactivate/<int:process_id>', methods=['POST'])
@login_required
def reactivate_process(process_id):
    lawyer_id, _ = get_current_lawyer_context()
    process = None
    if lawyer_id: process = Process.query.filter_by(id=process_id, lawyer_id=lawyer_id, status='archived').first()
    if not process: flash("Processo inválido.", "danger"); return redirect(request.referrer or url_for('archived_processes'))
    process.status = 'active'
    try: db.session.commit(); flash(f'Processo #{process.id} reativado.', 'success')
    except Exception as e: db.session.rollback(); app.logger.error(f"Erro ao reativar P-{process_id} L-{lawyer_id}: {e}"); flash('Erro ao reativar.', 'danger')
    return redirect(request.referrer or url_for('archived_processes'))


# --- Rota para Desenvolvedor ---
@app.route('/developer')
def developer_info():
     template_paths = ['admin/developer.html', 'developer.html']
     for path in template_paths:
         try: return render_template(path, title="Desenvolvedor")
         except: continue
     app.logger.warning("Template developer.html não encontrado.")
     return "Página do Desenvolvedor não encontrada.", 404


# --- Rotas para Notificações ---
@app.route('/notifications/new', methods=['POST'])
@login_required
@advogado_required
def create_notification():
    form = NotificationForm(formdata=request.form)
    if form.validate_on_submit():
         try:
             new_notification = Notification(message=form.message.data, created_by_lawyer_id=current_user.lawyer_profile_id)
             db.session.add(new_notification); db.session.commit(); flash("Notificação publicada!", "success")
             session.pop('lastShownNotificationId', None)
         except Exception as e: db.session.rollback(); app.logger.error(f"Erro criar notif L-{current_user.lawyer_profile_id}: {e}"); flash("Erro ao publicar.", "danger")
    else: flash("Erro ao publicar.", "danger"); flash_form_errors(form)
    return redirect(request.referrer or url_for('dashboard'))

@app.route('/notifications')
@login_required
def notifications():
    if not (current_user.is_gestor or current_user.is_acessor): abort(403)
    try:
        read_ids_subquery = db.session.query(notification_read_status.c.notification_id).filter_by(user_id=current_user.id).subquery()
        unread_notifications = (Notification.query.options(joinedload(Notification.creator_lawyer)).filter(Notification.id.notin_(read_ids_subquery)).order_by(Notification.created_at.desc()).all())
    except Exception as e: app.logger.error(f"Erro buscar notifs U-{current_user.id}: {e}"); flash("Erro ao carregar notificações.", "danger"); unread_notifications = []
    return render_template('notifications.html', notifications=unread_notifications, title="Notificações Pendentes")

@app.route('/notification/<int:notification_id>')
@login_required
def notification_detail(notification_id):
    if not (current_user.is_gestor or current_user.is_acessor): abort(403)
    notification = Notification.query.options(joinedload(Notification.creator_lawyer)).get(notification_id)
    if not notification: abort(404)
    already_read = db.session.query(notification_read_status).filter_by(user_id=current_user.id, notification_id=notification.id).first()
    if not already_read:
        try:
            stmt = notification_read_status.insert().values(user_id=current_user.id, notification_id=notification.id, read_at=datetime.now())
            db.session.execute(stmt); db.session.commit(); session.pop('lastShownNotificationId', None); flash("Notificação marcada como lida.", "info")
        except Exception as e: db.session.rollback(); app.logger.error(f"Erro marcar lida N-{notification_id} U-{current_user.id}: {e}"); flash("Erro ao marcar como lida.", "danger")
    return render_template('notification_detail.html', notification=notification, title="Detalhe da Notificação")

@app.route('/notification/mark_read/<int:notification_id>', methods=['POST'])
@login_required
def mark_notification_read(notification_id):
    if not (current_user.is_gestor or current_user.is_acessor): abort(403)
    notification = db.session.get(Notification, notification_id)
    if not notification: flash("Notificação não encontrada.", "warning"); return redirect(request.referrer or url_for('notifications'))
    already_read = db.session.query(notification_read_status).filter_by(user_id=current_user.id, notification_id=notification.id).first()
    if not already_read:
        try:
            stmt = notification_read_status.insert().values(user_id=current_user.id, notification_id=notification.id, read_at=datetime.now())
            db.session.execute(stmt); db.session.commit(); flash("Marcada como lida.", "success"); session.pop('lastShownNotificationId', None)
        except Exception as e: db.session.rollback(); app.logger.error(f"Erro marcar lida manual N-{notification_id} U-{current_user.id}: {e}"); flash("Erro ao marcar.", "danger")
    else: flash("Já estava marcada como lida.", "info")
    return redirect(url_for('notifications'))

@app.route('/notification/mark_unread/<int:notification_id>', methods=['POST'])
@login_required
def mark_notification_unread(notification_id):
    if not (current_user.is_gestor or current_user.is_acessor): abort(403)
    notification = db.session.get(Notification, notification_id)
    if not notification: flash("Notificação não encontrada.", "warning"); return redirect(request.referrer or url_for('notifications'))
    try:
        stmt = notification_read_status.delete().where((notification_read_status.c.user_id == current_user.id) & (notification_read_status.c.notification_id == notification_id))
        result = db.session.execute(stmt); db.session.commit()
        if result.rowcount > 0: flash("Marcada como NÃO lida.", "success"); session.pop('lastShownNotificationId', None)
        else: flash("Já estava marcada como não lida.", "info")
    except Exception as e: db.session.rollback(); app.logger.error(f"Erro marcar NÃO lida N-{notification_id} U-{current_user.id}: {e}"); flash("Erro ao marcar.", "danger")
    return redirect(request.referrer or url_for('notifications'))


# --- Execução do Servidor ---
if __name__ == '__main__':
    DEBUG_MODE = os.environ.get('FLASK_DEBUG', 'False').lower() in ('true', '1', 't')
    PORT = int(os.environ.get('PORT', 5000))
    # Use 0.0.0.0 para permitir acesso externo (necessário em muitos deploys)
    # Use 127.0.0.1 para acesso apenas local
    HOST = '0.0.0.0' if not DEBUG_MODE else '127.0.0.1'
    print(f" * Running on http://{HOST}:{PORT}/ (Debug: {DEBUG_MODE})")
    app.run(host=HOST, port=PORT, debug=DEBUG_MODE)