# models.py
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from datetime import datetime

db = SQLAlchemy()

# Tabela de Associação Many-to-Many: User (Acessor) <-> Lawyer
acessor_lawyer_assignments = db.Table('acessor_lawyer_assignments',
    db.Column('user_id', db.Integer, db.ForeignKey('user.id', ondelete='CASCADE'), primary_key=True),
    db.Column('lawyer_id', db.Integer, db.ForeignKey('lawyer.id', ondelete='CASCADE'), primary_key=True)
)

# Tabela de Associação Many-to-Many: User <-> Notification (Status de Leitura)
notification_read_status = db.Table('notification_read_status',
    db.Column('user_id', db.Integer, db.ForeignKey('user.id', ondelete='CASCADE'), primary_key=True),
    db.Column('notification_id', db.Integer, db.ForeignKey('notification.id', ondelete='CASCADE'), primary_key=True),
    db.Column('read_at', db.DateTime, default=datetime.now) # Consider db.func.now() for production DBs
)

# Modelo de Usuário para Login (Gestor, Advogado ou Acessor)
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    role = db.Column(db.String(20), nullable=False, default='advogado') # Papéis: 'advogado', 'gestor', 'acessor'
    is_approved = db.Column(db.Boolean, nullable=False, default=False)

    # Ligação UM-PARA-UM: User (advogado) -> Lawyer (perfil)
    # Se o Lawyer for deletado, seta lawyer_profile_id para NULL no User.
    lawyer_profile_id = db.Column(db.Integer, db.ForeignKey('lawyer.id', ondelete='SET NULL'), unique=True, nullable=True)
    # passive_deletes=True informa ao SQLAlchemy para não interferir na ação ondelete do DB.
    lawyer_profile = db.relationship('Lawyer', backref=db.backref('user_account', uselist=False, passive_deletes=True), foreign_keys=[lawyer_profile_id], lazy='joined')

    # Ligação MANY-TO-MANY: User (acessor) <-> Lawyer (perfis que assiste)
    # 'dynamic' permite aplicar filtros adicionais (ex: user.lawyers_assisted.order_by(...))
    lawyers_assisted = db.relationship(
        'Lawyer', secondary=acessor_lawyer_assignments,
        back_populates='assessores', lazy='dynamic'
    )

    # Relação MANY-TO-MANY: Notificações lidas por este usuário
    read_notifications = db.relationship(
        'Notification', secondary=notification_read_status,
        back_populates='readers', lazy='dynamic'
    )

    def __repr__(self):
        return f'<User {self.username} ({self.role})>'

    @property
    def is_gestor(self):
        return self.role == 'gestor'

    @property
    def is_advogado(self):
        return self.role == 'advogado'

    @property
    def is_acessor(self):
        return self.role == 'acessor'

# Modelo de Advogado (Perfil de dados)
class Lawyer(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False, unique=True)

    # Relações UM-PARA-MUITOS: Lawyer -> Clients, Processes, NotificationsCreated
    # cascade="all, delete" garante que ao deletar um Lawyer, seus Clients, Processes e Notifications criadas sejam deletados.
    clients = db.relationship('Client', backref='lawyer', lazy='dynamic', cascade="all, delete")
    processes = db.relationship('Process', backref='lawyer', lazy='dynamic', cascade="all, delete")
    notifications_created = db.relationship('Notification', backref='creator_lawyer', lazy='dynamic', foreign_keys='Notification.created_by_lawyer_id', cascade="all, delete")

    # Relação com Usuário Advogado (One-to-One via backref 'user_account' definido em User)

    # Relação com Usuários Assessores (Many-to-Many via 'acessor_lawyer_assignments')
    assessores = db.relationship(
        'User', secondary=acessor_lawyer_assignments,
        back_populates='lawyers_assisted', lazy='dynamic'
    )

    def __repr__(self):
        return f'<Lawyer {self.name}>'

    # Método para verificar se o perfil pode ser excluído (otimizado)
    def can_delete(self):
        # Verifica se existe PELO MENOS UM item relacionado que impediria a exclusão
        if self.clients.first() or \
           self.processes.first() or \
           self.user_account or \
           self.assessores.first() or \
           self.notifications_created.first(): # Adicionado verificação de notificações
            return False
        return True

# Modelo de Notificação
class Notification(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    message = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.now) # Consider db.func.now()
    # Ligação MUITOS-PARA-UM: Notification -> Lawyer (criador)
    # ondelete='CASCADE' deleta a notificação se o Lawyer criador for deletado.
    created_by_lawyer_id = db.Column(db.Integer, db.ForeignKey('lawyer.id', ondelete='CASCADE'), nullable=False)

    # Relação MANY-TO-MANY: Usuários que leram esta notificação
    readers = db.relationship(
        'User', secondary=notification_read_status,
        back_populates='read_notifications', lazy='dynamic'
    )

    def __repr__(self):
        return f'<Notification {self.id} by Lawyer {self.created_by_lawyer_id}>'

# Modelo de Cliente
class Client(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150), nullable=False)
    phone = db.Column(db.String(20), nullable=True)
    email = db.Column(db.String(120), nullable=True)
    address = db.Column(db.String(250), nullable=True)
    # CPF é validado na aplicação para garantir unicidade por advogado
    cpf = db.Column(db.String(14), nullable=False) # Tornando CPF obrigatório
    rg = db.Column(db.String(20), nullable=True)
    profession = db.Column(db.String(100), nullable=True)
    other_info = db.Column(db.Text, nullable=True)

    # Ligação MUITOS-PARA-UM: Client -> Lawyer
    # ondelete='CASCADE' deleta o cliente se o Lawyer for deletado.
    lawyer_id = db.Column(db.Integer, db.ForeignKey('lawyer.id', ondelete='CASCADE'), nullable=False)

    # Relações UM-PARA-MUITOS: Client -> Processes, Documents
    # cascade="all, delete" deleta Processos e Documentos se o Cliente for deletado.
    processes = db.relationship('Process', backref='client', lazy='dynamic', cascade="all, delete")
    documents = db.relationship('Document', backref='client', lazy='dynamic', cascade="all, delete")

    def __repr__(self):
        return f'<Client {self.name}>'

# Modelo de Processo
class Process(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    case_number = db.Column(db.String(50), nullable=True)
    description = db.Column(db.Text, nullable=False)
    status = db.Column(db.String(20), nullable=False, default='active') # Status: 'active', 'archived'
    updates = db.Column(db.Text, nullable=True) # Histórico de andamentos

    # Ligações MUITOS-PARA-UM: Process -> Client, Process -> Lawyer
    # ondelete='CASCADE' deleta o Processo se o Client ou o Lawyer forem deletados.
    client_id = db.Column(db.Integer, db.ForeignKey('client.id', ondelete='CASCADE'), nullable=False)
    lawyer_id = db.Column(db.Integer, db.ForeignKey('lawyer.id', ondelete='CASCADE'), nullable=False)

    # Relação UM-PARA-MUITOS: Process -> Deadlines
    # cascade="all, delete" deleta os Deadlines se o Processo for deletado.
    deadlines = db.relationship('Deadline', backref='process', lazy='dynamic', cascade="all, delete")

    def __repr__(self):
        return f'<Process {self.id} for Client {self.client_id}>'

# Modelo de Prazo
class Deadline(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    description = db.Column(db.Text, nullable=False)
    due_date = db.Column(db.Date, nullable=False)
    status = db.Column(db.String(20), nullable=False, default='open') # Status: 'open', 'completed', 'extended'

    # Ligação MUITOS-PARA-UM: Deadline -> Process
    # ondelete='CASCADE' deleta o Deadline se o Processo for deletado.
    process_id = db.Column(db.Integer, db.ForeignKey('process.id', ondelete='CASCADE'), nullable=False)

    def __repr__(self):
        return f'<Deadline {self.id} for Process {self.process_id}>'

# Modelo de Documento (Link)
class Document(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(200), nullable=False) # Nome descritivo do link
    storage_link = db.Column(db.String(500), nullable=False) # URL do documento/pasta
    upload_date = db.Column(db.DateTime, nullable=False, default=datetime.now) # Consider db.func.now()

    # Ligação MUITOS-PARA-UM: Document -> Client
    # ondelete='CASCADE' deleta o Document se o Client for deletado.
    client_id = db.Column(db.Integer, db.ForeignKey('client.id', ondelete='CASCADE'), nullable=False)

    def __repr__(self):
        return f'<Document {self.filename} for Client {self.client_id}>'