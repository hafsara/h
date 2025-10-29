# Architecture Multi-Applications avec SSO/AppToken/API

## 1. Vue d'ensemble de la sécurité

### Types de connexion
- **SSO User** : Utilisateur standard via Apigee SSO (JWT)
- **SSO Admin** : Admin via SSO + AppToken pour une app spécifique
- **API Client** : Serveur externe via ConsumerID + Secret (OAuth2 client credentials)

### Flux d'authentification global

```
┌─────────────────────────────────────────────────────────┐
│                    FRONTEND ANGULAR                      │
│  (Pas de app_name en localStorage)                       │
│  Session Bearer Token stocké en HttpOnly Cookie          │
└────────────────────┬────────────────────────────────────┘
                     │
                     ▼
┌───────────────────────────────────────────────────────── ┐
│                    APIGEE GATEWAY                        │
│  ├─ Authentification SSO (JWT validation)                │
│  ├─ Authentification API (ConsumerID/Secret)             │
│  └─ Injection header X-User-ID, X-Consumer-ID            │
└────────────────────┬────────────────────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────────────────┐
│                 FLASK BACKEND API                        │
│  ├─ Session Management (Redis/Database)                 │
│  ├─ Application Context Resolution                       │
│  ├─ Role-Based Access Control                            │
│  └─ Multi-App Switching Logic                            │
└──────────────────────────────────────────────────────────┘
```

---

## 2. Modèles de données backend

### Tables/Collections recommandées

```python
# ApplicationSession - stocke l'état de la session
class ApplicationSession(db.Model):
    __tablename__ = 'application_sessions'
    
    id = db.Column(db.String(36), primary_key=True)  # UUID
    user_id = db.Column(db.String(255), nullable=False, index=True)
    
    # Type de connexion
    connection_type = db.Column(db.Enum('SSO_USER', 'SSO_ADMIN', 'API_CLIENT'), nullable=False)
    
    # Application active actuellement
    current_app_id = db.Column(db.String(50), nullable=False, index=True)
    
    # Informations de la session
    session_token = db.Column(db.String(500), nullable=False, unique=True)
    consumer_id = db.Column(db.String(255), nullable=True)  # Pour API clients
    
    # Applications accessibles par cet utilisateur
    accessible_apps = db.Column(db.JSON, nullable=False)  # ["app1", "app2"]
    
    # Rôles utilisateur (denormalisé pour perf)
    roles = db.Column(db.JSON, nullable=False)  # {"app1": ["FORAS-admin"], "app2": ["viewer"]}
    
    # Timestamps
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_activity = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    expires_at = db.Column(db.DateTime, nullable=False)
    
    # État
    is_active = db.Column(db.Boolean, default=True)

# UserApplicationRole - mapping des rôles par app
class UserApplicationRole(db.Model):
    __tablename__ = 'user_application_roles'
    
    id = db.Column(db.String(36), primary_key=True)
    user_id = db.Column(db.String(255), nullable=False, index=True)
    app_id = db.Column(db.String(50), nullable=False, index=True)
    entitlements = db.Column(db.JSON, nullable=False)  # ["FORAS-admin", "FORAS-reviewer"]
    
    # Pour admin avec AppToken
    app_token_hash = db.Column(db.String(255), nullable=True)
    app_token_expires_at = db.Column(db.DateTime, nullable=True)
    
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    __table_args__ = (db.UniqueConstraint('user_id', 'app_id'),)

# ApplicationMetadata - configuration des apps
class ApplicationMetadata(db.Model):
    __tablename__ = 'application_metadata'
    
    app_id = db.Column(db.String(50), primary_key=True)
    name = db.Column(db.String(255), nullable=False)
    description = db.Column(db.String(500))
    
    # Require AppToken pour les admins
    requires_app_token = db.Column(db.Boolean, default=False)
    
    # Roles disponibles dans cette app
    available_roles = db.Column(db.JSON)  # ["admin", "reviewer", "viewer"]
    
    # Consumer IDs autorisés pour accès API
    authorized_consumer_ids = db.Column(db.JSON)  # ["client-123", "client-456"]
    
    is_active = db.Column(db.Boolean, default=True)

# APIClientCredentials - pour serveurs externes
class APIClientCredentials(db.Model):
    __tablename__ = 'api_client_credentials'
    
    consumer_id = db.Column(db.String(255), primary_key=True)
    # secret_hash = db.Column(db.String(255), nullable=False)
    
    # Applications auxquelles ce client peut accéder
    allowed_apps = db.Column(db.JSON, nullable=False)  # ["app1", "app2"]
    
    # Rôles automatiques pour ce client
    default_roles = db.Column(db.JSON, nullable=False)  # {"app1": ["reader"], "app2": ["reader"]}
    
    name = db.Column(db.String(255))
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_used = db.Column(db.DateTime)
```

---

## 3. Endpoints Flask - Gestion de session et contexte

### Architecture des endpoints

```python
from flask import Blueprint, request, jsonify, make_response
from flask_cors import cross_origin
from functools import wraps
import jwt
import json
from datetime import datetime, timedelta
from sqlalchemy import or_
import redis
import uuid

auth_bp = Blueprint('auth', __name__, url_prefix='/api/auth')
session_bp = Blueprint('session', __name__, url_prefix='/api/session')

# Redis pour cache du contexte (haute performance)
redis_client = redis.Redis(host='localhost', port=6379, db=0)

# =====================================================
# 1. MIDDLEWARE : Extraction du contexte Apigee
# =====================================================

def extract_apigee_context():
    """
    Récupère les infos injectées par Apigee :
    - X-User-ID : ID utilisateur SSO
    - X-Consumer-ID : ID client API (optionnel)
    - Authorization : Bearer token SSO (jwt)
    """
    context = {
        'user_id': request.headers.get('X-User-ID'),
        'consumer_id': request.headers.get('X-Consumer-ID'),
        'auth_header': request.headers.get('Authorization', ''),
    }
    return context

# =====================================================
# 2. AUTH DECORATORS
# =====================================================
# TODO
def require_session(f):
    """Vérifie qu'une session valide existe pour cet utilisateur."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        apigee_ctx = extract_apigee_context()
        
        session_token = request.cookies.get('session_token')
        if not session_token:
            return jsonify({'error': 'No session token'}), 401
        
        session = ApplicationSession.query.filter_by(
            session_token=session_token,
            user_id=apigee_ctx['user_id'],
            is_active=True
        ).first()
        
        if not session or session.expires_at < datetime.utcnow():
            return jsonify({'error': 'Session expired or invalid'}), 401
        
        request.app_session = session
        request.apigee_context = apigee_ctx
        
        return f(*args, **kwargs)
    
    return decorated_function
# TODO
def require_user(f):
    """Vérifie que l'utilisateur a le rôle ADMIN pour l'app courante."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        session = request.app_session
        app_id = session.current_app_id
        
        if 'FOURAS-user' not in session.roles.get(app_id, []): # 
            return jsonify({'error': 'Insufficient privileges'}), 403
        
        return f(*args, **kwargs)
    
    return decorated_function
# TODO
def require_admin(f):
    """Vérifie que l'utilisateur a le rôle ADMIN pour l'app courante."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        session = request.app_session
        app_id = session.current_app_id
        
        if 'FOURAS-admin' not in session.roles.get(app_id, []): # 
            return jsonify({'error': 'Insufficient privileges'}), 403
        
        return f(*args, **kwargs)
    
    return decorated_function

# TODO
@auth_bp.route('/login/sso-admin', methods=['POST'])
@cross_origin()
def login_sso_admin():
    """
    Admin via SSO + AppToken.
    Apigee valide le SSO (X-User-ID).
    On vérifie l'AppToken, on récupère l'app associée.
    """
    apigee_ctx = extract_apigee_context()
    user_id = apigee_ctx['user_id']
    app_token = request.json.get('app_token')
    
    if not user_id or not app_token:
        return jsonify({'error': 'Missing credentials'}), 400
    
    # Vérifier AppToken & récupérer l'app
    # app_role = _verify_app_token(user_id, app_token)
    # if not app_role:
    #     return jsonify({'error': 'Invalid app token'}), 401
    # 
    # app_id = app_role.app_id
    
    # Vérifier que l'app existe et est active
    app_metadata = ApplicationMetadata.query.filter_by(app_id=app_id, is_active=True).first()
    if not app_metadata:
        return jsonify({'error': 'Application not found'}), 404
    
    # Créer session admin
    session_token = str(uuid.uuid4())
    roles = {app_id: app_role.entitlements}
    
    app_session = ApplicationSession(
        id=str(uuid.uuid4()),
        user_id=user_id,
        connection_type='SSO_ADMIN',
        current_app_id=app_id,
        session_token=session_token,
        accessible_apps=[app_id],  # Admin limité à 1 app
        roles=roles,
        expires_at=datetime.utcnow() + timedelta(hours=4)
    )
    # todo il faut que app_name soit a la liste je laise le applications/verify et j'ajoute à la fin le /login
    db.session.add(app_session)
    db.session.commit()
    _cache_session(app_session)
    
    response = make_response(jsonify({
        'success': True,
        'app_id': app_id,
        'roles': app_role.entitlements,
        'message': 'Admin logged in successfully'
    }), 200)
    
    response.set_cookie('session_token', session_token, max_age=4*3600, httponly=True, secure=True, samesite='Strict')
    
    return response

# TODO à creser
@auth_bp.route('/login/api-client', methods=['POST'])
def login_api_client():
    """
    Client API (serveur-à-serveur) via ConsumerID + Secret.
    Endpoint interne - pas d'authentification SSO requise ici.
    """
    consumer_id = request.json.get('consumer_id')
    secret = request.json.get('secret')
    
    if not consumer_id or not secret:
        return jsonify({'error': 'Missing credentials'}), 400
    
    # Vérifier credentails
    client = APIClientCredentials.query.filter_by(consumer_id=consumer_id, is_active=True).first()
    if not client or not _verify_secret(secret, client.secret_hash):
        return jsonify({'error': 'Invalid credentials'}), 401
    
    # Créer session API
    session_token = str(uuid.uuid4())
    
    app_session = ApplicationSession(
        id=str(uuid.uuid4()),
        user_id=f"api-client:{consumer_id}",
        connection_type='API_CLIENT',
        current_app_id=client.allowed_apps[0],  # App par défaut
        session_token=session_token,
        consumer_id=consumer_id,
        accessible_apps=client.allowed_apps,
        roles={app: client.default_roles.get(app, ['reader']) for app in client.allowed_apps},
        expires_at=datetime.utcnow() + timedelta(hours=24)
    )
    
    db.session.add(app_session)
    db.session.commit()
    _cache_session(app_session)
    
    client.last_used = datetime.utcnow()
    db.session.commit()
    
    return jsonify({
        'success': True,
        'access_token': session_token,
        'token_type': 'Bearer',
        'expires_in': 24*3600
    }), 200

# =====================================================
# todo je garde GESTION DU CONTEXTE DE SESSION
# =====================================================

@session_bp.route('/context', methods=['GET'])
@require_session
def get_session_context():
    """
    Endpoint clé : retourne le contexte applicatif sans révéler le app_name au localStorage.
    Le frontend obtient l'état complet de sa session.
    """
    session = request.app_session
    
    return jsonify({
        'session_id': session.id,
        'user_type': session.connection_type,
        'current_app': {
            'id': session.current_app_id,
            'metadata': _get_app_metadata_public(session.current_app_id)
        },
        'accessible_apps': [
            {
                'id': app_id,
                'metadata': _get_app_metadata_public(app_id),
                'roles': session.roles.get(app_id, [])
            }
            for app_id in session.accessible_apps
        ],
        'user_roles': session.roles.get(session.current_app_id, []),
        #permissions': _compute_permissions(session),
        'session_expires_at': session.expires_at.isoformat(),
        'last_activity': session.last_activity.isoformat()
    }), 200

@session_bp.route('/refresh', methods=['POST'])
@require_session
def refresh_session():
    """
    Renouvelle la session (keep-alive).
    """
    session = request.app_session
    session.last_activity = datetime.utcnow()
    
    # Extend expiry si proche
    if session.expires_at - datetime.utcnow() < timedelta(hours=1):
        session.expires_at = datetime.utcnow() + timedelta(hours=8)
    
    db.session.commit()
    _cache_session(session)
    
    return jsonify({
        'success': True,
        'expires_at': session.expires_at.isoformat()
    }), 200

@session_bp.route('/logout', methods=['POST'])
@require_session
def logout():
    """
    Ferme la session.
    """
    session = request.app_session
    session.is_active = False
    db.session.commit()
    
    # Invalider le cache
    redis_client.delete(f"session:{session.id}")
    
    response = make_response(jsonify({'success': True}), 200)
    response.set_cookie('session_token', '', max_age=0)
    
    return response

# =====================================================
# 5. EXEMPLE : Endpoint protégé (admin only)
# =====================================================

forms_bp = Blueprint('forms', __name__, url_prefix='/api/forms')

@forms_bp.route('/validate', methods=['POST'])
@cross_origin()
@require_session
@require_admin
def validate_form():
    """
    Seuls les admins FORAS peuvent valider des formulaires.
    """
    session = request.app_session
    form_id = request.json.get('form_id')
    
    # Logique de validation
    # ...
    
    return jsonify({
        'success': True,
        'form_id': form_id,
        'validated_by': session.user_id,
        'app_id': session.current_app_id
    }), 200

# =====================================================
# 6. UTILITAIRES (helpers)
# =====================================================

def _get_user_accessible_apps(user_id):
    """Retourne les apps accessibles par un utilisateur."""
    roles = UserApplicationRole.query.filter_by(user_id=user_id).all()
    return list(set([role.app_id for role in roles]))

def _get_user_roles_for_apps(user_id, app_ids):
    """Retourne les rôles d'un utilisateur par app."""
    roles = UserApplicationRole.query.filter(
        UserApplicationRole.user_id == user_id,
        UserApplicationRole.app_id.in_(app_ids)
    ).all()
    
    return {role.app_id: role.entitlements for role in roles}

def _verify_app_token(user_id, app_token):
    """Vérifie un AppToken et retourne la relation user-app."""
    # Hash du token reçu
    token_hash = _hash_token(app_token)
    
    role = UserApplicationRole.query.filter_by(user_id=user_id).filter(
        UserApplicationRole.app_token_hash == token_hash,
        UserApplicationRole.app_token_expires_at > datetime.utcnow()
    ).first()
    
    return role

def _verify_secret(secret, secret_hash):
    """Vérifie le secret API avec bcrypt."""
    import bcrypt
    return bcrypt.checkpw(secret.encode(), secret_hash.encode())

def _hash_token(token):
    """Hash d'un token ou secret."""
    import hashlib
    return hashlib.sha256(token.encode()).hexdigest()
# todo a garder aussi
def _cache_session(app_session):
    """Stocke la session en cache Redis."""
    session_data = {
        'id': app_session.id,
        'user_id': app_session.user_id,
        'connection_type': app_session.connection_type,
        'current_app_id': app_session.current_app_id,
        'accessible_apps': app_session.accessible_apps,
        'roles': app_session.roles,
    }
    redis_client.setex(
        f"session:{app_session.id}",
        int((app_session.expires_at - datetime.utcnow()).total_seconds()),
        json.dumps(session_data, default=str)
    )

def _get_app_metadata_public(app_id):
    """Retourne les métadonnées publiques d'une app (sans secrets)."""
    app = ApplicationMetadata.query.filter_by(app_id=app_id).first()
    if not app:
        return None
    
    return {
        'id': app.app_id,
        'name': app.name,
        'description': app.description,
        'requires_app_token': app.requires_app_token
    }

def _compute_permissions(session):
    """Calcule les permissions basées sur les rôles."""
    app_id = session.current_app_id
    roles = session.roles.get(app_id, [])
    
    permissions = {
        'can_validate': 'FORAS-admin' in roles,
        'can_review': 'FORAS-admin' in roles or 'FORAS-reviewer' in roles,
        'can_read': True
    }
    
    return permissions
```

---

## 4. Frontend Angular - Service et gestion du contexte

### ApplicationContextService

```typescript
import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { BehaviorSubject, Observable, interval } from 'rxjs';
import { tap, switchMap, catchError } from 'rxjs/operators';

export interface AppContext {
  session_id: string;
  user_type: 'SSO_USER' | 'SSO_ADMIN' | 'API_CLIENT';
  current_app: {
    id: string;
    metadata: { id: string; name: string; description: string; requires_app_token: boolean };
  };
  accessible_apps: Array<{
    id: string;
    metadata: { id: string; name: string; description: string };
    roles: string[];
  }>;
  user_roles: string[];
  permissions: {
    can_validate: boolean;
    can_review: boolean;
    can_read: boolean;
  };
  session_expires_at: string;
  last_activity: string;
}

@Injectable({ providedIn: 'root' })
export class ApplicationContextService {
  private contextSubject = new BehaviorSubject<AppContext | null>(null);
  public context$ = this.contextSubject.asObservable();

  private loadingSubject = new BehaviorSubject<boolean>(false);
  public loading$ = this.loadingSubject.asObservable();

  constructor(private http: HttpClient) {
    // Charger le contexte au démarrage
    this.loadContext();
    
    // Refresh la session toutes les 30 minutes
    interval(30 * 60 * 1000)
      .pipe(
        switchMap(() => this.refreshSession()),
        catchError(err => {
          console.error('Session refresh failed:', err);
          return [];
        })
      )
      .subscribe();
  }

  // ================== CHARGEMENT DU CONTEXTE ==================

  loadContext(): Observable<AppContext> {
    this.loadingSubject.next(true);
    return this.http.get<AppContext>('/api/session/context').pipe(
      tap(context => {
        this.contextSubject.next(context);
        this.loadingSubject.next(false);
      }),
      catchError(error => {
        console.error('Failed to load context:', error);
        this.loadingSubject.next(false);
        throw error;
      })
    );
  }

  // ================== ACCÈS AU CONTEXTE COURANT ==================

  get currentContext(): AppContext | null {
    return this.contextSubject.value;
  }

  get currentAppId(): string | null {
    return this.contextSubject.value?.current_app.id ?? null;
  }

  get currentAppName(): string | null {
    return this.contextSubject.value?.current_app.metadata.name ?? null;
  }

  get userRoles(): string[] {
    return this.contextSubject.value?.user_roles ?? [];
  }

  get permissions(): AppContext['permissions'] | null {
    return this.contextSubject.value?.permissions ?? null;
  }

  get accessible_apps(): Array<{ id: string; name: string; roles: string[] }> {
    return (this.contextSubject.value?.accessible_apps ?? []).map(app => ({
      id: app.id,
      name: app.metadata.name,
      roles: app.roles
    }));
  }

  // ================== SWITCH D'APPLICATION ==================

  switchApplication(appId: string): Observable<any> {
    return this.http.post('/api/session/switch-app', { app_id: appId }).pipe(
      tap(response => {
        // Recharger le contexte complet
        this.loadContext().subscribe();
      })
    );
  }

  // ================== KEEP-ALIVE ==================

  refreshSession(): Observable<any> {
    return this.http.post('/api/session/refresh', {});
  }

  // ================== LOGOUT ==================

  logout(): Observable<any> {
    return this.http.post('/api/session/logout', {}).pipe(
      tap(() => {
        this.contextSubject.next(null);
      })
    );
  }

  // ================== UTILITAIRES ==================

  hasRole(role: string): boolean {
    return this.userRoles.includes(role);
  }

  hasPermission(permission: keyof AppContext['permissions']): boolean {
    return this.permissions?.[permission] ?? false;
  }

  canAccessApp(appId: string): boolean {
    return this.accessible_apps.some(app => app.id === appId);
  }

  isSessionExpired(): boolean {
    const context = this.contextSubject.value;
    if (!context) return true;
    return new Date(context.session_expires_at) < new Date();
  }
}
```

### Component : App Selector & Navigation

```typescript
import { Component, OnInit } from '@angular/core';
import { ApplicationContextService } from './services/application-context.service';
import { Observable } from 'rxjs';

@Component({
  selector: 'app-header',
  template: `
    <header class="app-header">
      <div class="brand">
        <h1>{{ currentAppName$ | async }}</h1>
      </div>

      <div class="app-switcher" *ngIf="(accessibleApps$ | async) as apps">
        <ng-container *ngIf="apps.length > 1">
          <label>Application :</label>
          <select 
            [value]="currentAppId$ | async"
            (change)="onAppChange($event)"
            class="app-select"
          >
            <option 
              *ngFor="let app of apps" 
              [value]="app.id"
            >
              {{ app.name }} ({{ app.roles.join(', ') }})
            </option>
          </select>
        </ng-container>
      </div>

      <div class="user-info">
        <span class="user-type" [ngClass]="(userType$ | async) | lowercase">
          {{ userType$ | async }}
        </span>
        <span class="session-status">
          <ng-container *ngIf="!(sessionExpiring$ | async); else expiringWarning">
            ✓ Session active
          </ng-container>
          <ng-template #expiringWarning>
            <span class="warning">⚠️ Session expiring soon</span>
          </ng-template>
        </span>
        <button (click)="logout()" class="logout-btn">Logout</button>
      </div>
    </header>
  `,
  styles: [`
    .app-header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      padding: 1rem;
      background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
      color: white;
      box-shadow: 0 2px 8px rgba(0,0,0,0.1);
    }
    .app-switcher {
      display: flex;
      align-items: center;
      gap: 0.5rem;
    }
    .app-select {
      padding: 0.5rem;
      border-radius: 4px;
      border: none;
      cursor: pointer;
    }
    .session-status.warning {
      color: #ffc107;
      font-weight: bold;
    }
    .logout-btn {
      padding: 0.5rem 1rem;
      background: rgba(255,255,255,0.2);
      border: 1px solid white;
      color: white;
      border-radius: 4px;
      cursor: pointer;
      transition: all 0.3s ease;
    }
    .logout-btn:hover {
      background: rgba(255,255,255,0.3);
    }
  `]
})
export class HeaderComponent implements OnInit {
  currentAppId$: Observable<string | null>;
  currentAppName$: Observable<string | null>;
  accessibleApps$: Observable<Array<{ id: string; name: string; roles: string[] }>>;
  userType$: Observable<string | null>;
  sessionExpiring$: Observable<boolean>;

  constructor(public appContextService: ApplicationContextService) {
    this.currentAppId$ = this.appContextService.context$.pipe(
      switchMap(ctx => of(ctx?.current_app.id ?? null))
    );
    
    this.currentAppName$ = this.appContextService.context$.pipe(
      switchMap(ctx => of(ctx?.current_app.metadata.name ?? null))
    );
    
    this.accessibleApps$ = this.appContextService.context$.pipe(
      switchMap(ctx => of(ctx?.accessible_apps.map(app => ({
        id: app.id,
        name: app.metadata.name,
        roles: app.roles
      })) ?? []))
    );
    
    this.userType$ = this.appContextService.context$.pipe(
      switchMap(ctx => of(ctx?.user_type ?? null))
    );
    
    this.sessionExpiring$ = this.appContextService.context$.pipe(
      switchMap(ctx => {
        if (!ctx) return of(false);
        const expiresAt = new Date(ctx.session_expires_at).getTime();
        const now = Date.now();
        const timeLeft = expiresAt - now;
        return of(timeLeft < 15 * 60 * 1000); // Avertir 15 min avant expiry
      })
    );
  }

  ngOnInit(): void {}

  onAppChange(event: any): void {
    const appId = event.target.value;
    this.appContextService.switchApplication(appId).subscribe({
      next: () => console.log(`Switched to app: ${appId}`),
      error: (err) => alert(`Failed to switch app: ${err.message}`)
    });
  }

  logout(): void {
    if (confirm('Êtes-vous sûr de vouloir vous déconnecter ?')) {
      this.appContextService.logout().subscribe({
        next: () => window.location.href = '/login',
        error: (err) => console.error('Logout failed:', err)
      });
    }
  }
}
```

### Component : Dashboard avec filtrage par application

```typescript
import { Component, OnInit } from '@angular/core';
import { ApplicationContextService } from './services/application-context.service';
import { Observable } from 'rxjs';
import { map } from 'rxjs/operators';

@Component({
  selector: 'app-dashboard',
  template: `
    <div class="dashboard" *ngIf="context$ | async as context">
      <section class="app-info">
        <h2>{{ context.current_app.metadata.name }}</h2>
        <p class="description">{{ context.current_app.metadata.description }}</p>
        
        <div class="context-details">
          <div class="detail">
            <label>Type de connexion :</label>
            <span [ngClass]="context.user_type | lowercase">
              {{ _formatUserType(context.user_type) }}
            </span>
          </div>
          
          <div class="detail">
            <label>Rôles :</label>
            <span class="roles">
              <span *ngFor="let role of context.user_roles" class="role-badge">
                {{ role }}
              </span>
            </span>
          </div>
          
          <div class="detail">
            <label>Permissions :</label>
            <span class="permissions">
              <span *ngIf="context.permissions.can_validate" class="perm-badge success">
                ✓ Valider
              </span>
              <span *ngIf="context.permissions.can_review" class="perm-badge success">
                ✓ Revue
              </span>
              <span *ngIf="context.permissions.can_read" class="perm-badge">
                ✓ Lecture
              </span>
            </span>
          </div>
        </div>
      </section>

      <!-- Admin Panel - Visible only if user has admin permissions -->
      <section class="admin-panel" *ngIf="context.permissions.can_validate">
        <h3>Panneau d'administration</h3>
        <app-form-validator [appId]="context.current_app.id"></app-form-validator>
      </section>

      <!-- Forms List - Visible for all authenticated users -->
      <section class="forms-list">
        <h3>Formulaires</h3>
        <app-forms-table 
          [appId]="context.current_app.id"
          [userRoles]="context.user_roles"
          [canValidate]="context.permissions.can_validate"
        ></app-forms-table>
      </section>

      <!-- Session Info -->
      <section class="session-info">
        <details>
          <summary>Informations de session</summary>
          <div class="session-details">
            <p><strong>Session ID :</strong> {{ context.session_id }}</p>
            <p><strong>Expire à :</strong> {{ context.session_expires_at | date:'medium' }}</p>
            <p><strong>Dernière activité :</strong> {{ context.last_activity | date:'medium' }}</p>
          </div>
        </details>
      </section>
    </div>
  `,
  styles: [`
    .dashboard {
      max-width: 1200px;
      margin: 2rem auto;
      padding: 0 1rem;
    }
    
    section {
      background: white;
      border-radius: 8px;
      padding: 2rem;
      margin-bottom: 2rem;
      box-shadow: 0 1px 3px rgba(0,0,0,0.1);
    }
    
    h2 { color: #333; margin-bottom: 0.5rem; }
    h3 { color: #555; border-bottom: 2px solid #667eea; padding-bottom: 0.5rem; }
    
    .description {
      color: #666;
      font-size: 0.95rem;
      margin-bottom: 1.5rem;
    }
    
    .context-details {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
      gap: 1rem;
      background: #f5f7ff;
      padding: 1rem;
      border-radius: 6px;
    }
    
    .detail {
      display: flex;
      flex-direction: column;
    }
    
    .detail label {
      font-weight: bold;
      color: #333;
      margin-bottom: 0.3rem;
      font-size: 0.85rem;
      text-transform: uppercase;
      color: #999;
    }
    
    .role-badge, .perm-badge {
      display: inline-block;
      padding: 0.4rem 0.8rem;
      margin-right: 0.5rem;
      margin-bottom: 0.3rem;
      border-radius: 4px;
      font-size: 0.85rem;
      font-weight: 500;
    }
    
    .role-badge {
      background: #e3f2fd;
      color: #1976d2;
    }
    
    .perm-badge {
      background: #f0f4c3;
      color: #827717;
    }
    
    .perm-badge.success {
      background: #c8e6c9;
      color: #2e7d32;
    }
    
    .admin-panel {
      background: #fff3e0;
      border-left: 4px solid #ff9800;
    }
    
    .session-info details {
      cursor: pointer;
    }
    
    .session-details {
      margin-top: 1rem;
      padding: 1rem;
      background: #f5f5f5;
      border-radius: 4px;
      font-size: 0.9rem;
      font-family: monospace;
    }
    
    .session-details p {
      margin: 0.5rem 0;
    }
    
    .sso_user { color: #1976d2; }
    .sso_admin { color: #d32f2f; font-weight: bold; }
    .api_client { color: #388e3c; }
  `]
})
export class DashboardComponent implements OnInit {
  context$: Observable<any>;

  constructor(public appContextService: ApplicationContextService) {
    this.context$ = this.appContextService.context$;
  }

  ngOnInit(): void {
    // Context est auto-géré par le service
  }

  _formatUserType(userType: string): string {
    const map = {
      'SSO_USER': 'Utilisateur SSO',
      'SSO_ADMIN': 'Admin via AppToken',
      'API_CLIENT': 'Client API'
    };
    return map[userType as keyof typeof map] || userType;
  }
}
```

### Component : Validation de formulaires (admin only)

```typescript
import { Component, Input, OnInit } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { ApplicationContextService } from './services/application-context.service';

@Component({
  selector: 'app-form-validator',
  template: `
    <div class="form-validator">
      <h4>Validation de formulaires</h4>
      
      <div class="search-box">
        <input 
          type="text" 
          placeholder="Rechercher un formulaire..."
          [(ngModel)]="searchQuery"
          (change)="onSearch()"
        />
      </div>

      <div *ngIf="loading" class="loading">Chargement...</div>

      <div *ngIf="!loading && forms.length === 0" class="no-data">
        Aucun formulaire en attente de validation
      </div>

      <table *ngIf="!loading && forms.length > 0" class="forms-table">
        <thead>
          <tr>
            <th>ID</th>
            <th>Utilisateur</th>
            <th>Date</th>
            <th>Statut</th>
            <th>Actions</th>
          </tr>
        </thead>
        <tbody>
          <tr *ngFor="let form of forms" [ngClass]="form.status | lowercase">
            <td>{{ form.id }}</td>
            <td>{{ form.submitted_by }}</td>
            <td>{{ form.created_at | date:'short' }}</td>
            <td class="status-badge">{{ form.status }}</td>
            <td class="actions">
              <button 
                (click)="validateForm(form.id)"
                [disabled]="form.status !== 'PENDING'"
                class="btn-validate"
              >
                ✓ Valider
              </button>
              <button 
                (click)="rejectForm(form.id)"
                [disabled]="form.status !== 'PENDING'"
                class="btn-reject"
              >
                ✗ Rejeter
              </button>
            </td>
          </tr>
        </tbody>
      </table>
    </div>
  `,
  styles: [`
    .form-validator {
      padding: 1rem 0;
    }

    .search-box {
      margin-bottom: 1rem;
    }

    .search-box input {
      width: 100%;
      max-width: 400px;
      padding: 0.5rem;
      border: 1px solid #ddd;
      border-radius: 4px;
    }

    .loading, .no-data {
      text-align: center;
      padding: 2rem;
      color: #999;
    }

    .forms-table {
      width: 100%;
      border-collapse: collapse;
      margin-top: 1rem;
    }

    .forms-table th {
      background: #667eea;
      color: white;
      padding: 0.75rem;
      text-align: left;
      font-weight: 600;
    }

    .forms-table td {
      padding: 0.75rem;
      border-bottom: 1px solid #eee;
    }

    .forms-table tbody tr:hover {
      background: #f5f5f5;
    }

    .status-badge {
      font-weight: bold;
      padding: 0.25rem 0.5rem;
      border-radius: 3px;
    }

    .pending .status-badge {
      background: #fff3cd;
      color: #856404;
    }

    .validated .status-badge {
      background: #d4edda;
      color: #155724;
    }

    .rejected .status-badge {
      background: #f8d7da;
      color: #721c24;
    }

    .actions {
      display: flex;
      gap: 0.5rem;
    }

    button {
      padding: 0.4rem 0.8rem;
      border: none;
      border-radius: 4px;
      cursor: pointer;
      font-size: 0.85rem;
      font-weight: 500;
      transition: all 0.3s ease;
    }

    .btn-validate {
      background: #4caf50;
      color: white;
    }

    .btn-validate:hover:not(:disabled) {
      background: #45a049;
    }

    .btn-reject {
      background: #f44336;
      color: white;
    }

    .btn-reject:hover:not(:disabled) {
      background: #da190b;
    }

    button:disabled {
      opacity: 0.5;
      cursor: not-allowed;
    }
  `]
})
export class FormValidatorComponent implements OnInit {
  @Input() appId: string = '';

  forms: any[] = [];
  loading = false;
  searchQuery = '';

  constructor(
    private http: HttpClient,
    private appContext: ApplicationContextService
  ) {}

  ngOnInit(): void {
    this.loadForms();
  }

  loadForms(): void {
    this.loading = true;
    this.http.get<any[]>(`/api/forms?app_id=${this.appId}&status=PENDING`)
      .subscribe({
        next: (data) => {
          this.forms = data;
          this.loading = false;
        },
        error: (err) => {
          console.error('Failed to load forms:', err);
          this.loading = false;
        }
      });
  }

  onSearch(): void {
    // Filtrer localement
    if (!this.searchQuery) {
      this.loadForms();
      return;
    }
    // Logique de filtrage...
  }

  validateForm(formId: string): void {
    this.http.post(`/api/forms/validate`, { form_id: formId })
      .subscribe({
        next: (response) => {
          alert('Formulaire validé avec succès');
          this.loadForms();
        },
        error: (err) => alert(`Erreur: ${err.error?.error}`)
      });
  }

  rejectForm(formId: string): void {
    const reason = prompt('Raison du rejet:');
    if (!reason) return;

    this.http.post(`/api/forms/reject`, { form_id: formId, reason })
      .subscribe({
        next: () => {
          alert('Formulaire rejeté');
          this.loadForms();
        },
        error: (err) => alert(`Erreur: ${err.error?.error}`)
      });
  }
}
```

---

## 5. Configuration Apigee - Injecter les headers

```xml
<!-- Apigee Policy: Extract User from JWT -->
<ExtractVariables name="ExtractUserFromJWT">
  <Source>request.header.Authorization</Source>
  <JSONPayload>
    <Variable name="user_id">$.sub</Variable>
    <Variable name="email">$.email</Variable>
  </JSONPayload>
</ExtractVariables>

<!-- Set headers for backend -->
<AssignMessage name="InjectUserContext">
  <Add>
    <Headers>
      <Header name="X-User-ID">{user_id}</Header>
      <Header name="X-Consumer-ID">{client_id}</Header>
    </Headers>
  </Add>
</AssignMessage>

<!-- Backend target -->
<TargetEndpoint name="backend">
  <PreFlow>
    <Request>
      <Step>
        <Name>ExtractUserFromJWT</Name>
      </Step>
      <Step>
        <Name>InjectUserContext</Name>
      </Step>
    </Request>
  </PreFlow>
  <HTTPTargetConnection>
    <URL>http://backend-api:5000</URL>
  </HTTPTargetConnection>
</TargetEndpoint>
```

---

## 6. Diagramme complet de flux

```
┌─────────────────────────────────────────────────────────────┐
│                  FLOW COMPLET (Multi-App)                   │
└─────────────────────────────────────────────────────────────┘

1. LOGIN UTILISATEUR STANDARD (SSO)
════════════════════════════════════════
User → [SSO Page] → Apigee validates JWT → Injects X-User-ID
                          ↓
                    POST /api/auth/login/sso-user
                          ↓
    Flask: _get_user_accessible_apps(user_id)
         → [app1, app2, app3] (from DB)
                          ↓
    Create ApplicationSession {
      current_app_id: app1  (default)
      accessible_apps: [app1, app2, app3]
      roles: {app1: [viewer], app2: [admin], app3: [viewer]}
    }
                          ↓
    Set HttpOnly Cookie: session_token
    Return: app1 + metadata
    Return: app1 + metadata
                          ↓
    Angular: Load context via GET /api/session/context
    Store in BehaviorSubject (NO localStorage)
    Display: App1 name in header, apps in switcher

2. SWITCH D'APPLICATION
════════════════════════════════════════
User clicks: <select app2>
                          ↓
Angular: appContextService.switchApplication('app2')
         POST /api/session/switch-app {app_id: 'app2'}
                          ↓
    Flask: Verify app2 in session.accessible_apps
           Update session.current_app_id = 'app2'
           Return: app2 metadata + roles for app2
                          ↓
Angular: Reload context, update BehaviorSubject
         UI re-renders with app2 name & permissions

3. ADMIN VALIDATION (AppToken)
════════════════════════════════════════
Admin navigates to /login/admin
Enters: user credentials (SSO) + app_token
                          ↓
POST /api/auth/login/sso-admin {app_token: "..."}
                          ↓
    Flask: _verify_app_token(user_id, app_token)
           Check: app_token_hash matches, not expired
           Return: app_id + entitlements
                          ↓
    Create ApplicationSession {
      connection_type: 'SSO_ADMIN'
      current_app_id: app2
      accessible_apps: [app2]  (ADMIN LIMITÉ À 1 APP)
      roles: {app2: [FORAS-admin]}
    }
                          ↓
Angular: Load context + display admin panel
         Show form validation section (can_validate = true)

4. ADMIN VALIDE UN FORMULAIRE
════════════════════════════════════════
Admin clicks: "Valider" button
                          ↓
Angular: POST /api/forms/validate {form_id: "form-123"}
                          ↓
    Flask: @require_session @require_admin
           Middleware verify: 'FORAS-admin' in roles[current_app_id]
           If INVALID → 403 Forbidden
                          ↓
           If VALID: Process validation
           Return: {success: true, validated_by: user_id}
                          ↓
Angular: Reload forms list, show success message

5. API CLIENT ACCESS (ConsumerID/Secret)
════════════════════════════════════════
External server:
  POST /api/auth/login/api-client
    {consumer_id: "client-123", secret: "..."}
                          ↓
    Flask: Verify credentials
           consumer_id → find APIClientCredentials
           secret → bcrypt.checkpw(secret, hash)
                          ↓
    Create ApplicationSession {
      user_id: "api-client:client-123"
      connection_type: 'API_CLIENT'
      current_app_id: app1
      accessible_apps: [app1, app2]
      roles: {app1: [reader], app2: [reader]}
    }
                          ↓
    Return: {access_token: session_token, expires_in: 86400}
                          ↓
External server: Use session_token as Bearer token
  GET /api/forms?app_id=app1
  Authorization: Bearer {session_token}
                          ↓
    Flask: @require_session validates Bearer token
           Fetch forms for app1, respecting API client read-only perms
           Return: Form data (filtered)

6. KEEP-ALIVE & SESSION REFRESH
════════════════════════════════════════
Angular: Every 5 minutes
  POST /api/session/refresh
                          ↓
    Flask: Extend session expiry if < 1h remaining
           Update last_activity timestamp
           Update Redis cache
                          ↓
Angular: Monitor expires_at, warn if < 15 min
```

---

## 7. Sécurité - Checklist

✅ **Authentification**
- [x] JWT validé par Apigee (X-User-ID injecté)
- [x] AppToken hashé en DB (SHA256 ou bcrypt)
- [x] API Client Secret hashé (bcrypt)
- [x] Session token unique (UUID)

✅ **Stockage côté client**
- [x] Pas de app_name en localStorage
- [x] Token en HttpOnly Cookie (inaccessible à JS)
- [x] Contexte dans BehaviorSubject (memory only)

✅ **RBAC (Role-Based Access Control)**
- [x] Rôles denormalisés en session pour perf
- [x] Entitlements validés à chaque requête
- [x] Permissions calculées server-side

✅ **Isolation multi-app**
- [x] User ne peut switcher que vers apps accessible
- [x] Admin limité à 1 seule app
- [x] API Client limité aux apps autorisées

✅ **Rate Limiting & DoS**
- [x] Implement rate limiting sur /login
- [x] Session expiry enforced
- [x] Redis TTL sur sessions

✅ **Audit & Logging**
- [x] Log connexions (user_id, app_id, type, timestamp)
- [x] Log actions sensibles (validate, switch-app)
- [x] Track API client usage (last_used timestamp)

---

## 8. Déploiement & Points d'attention

### Variables d'environnement

```bash
# Flask
FLASK_ENV=production
SECRET_KEY=<random-secret-key>
JWT_SECRET=<from-apigee>

# Database
DATABASE_URL=postgresql://user:pass@localhost:5432/app_context
REDIS_URL=redis://localhost:6379/0

# Apigee
APIGEE_API_URL=https://apigee.org/api
```

### Dependencies

```python
Flask==3.0.0
Flask-SQLAlchemy==3.0.0
Flask-CORS==4.0.0
redis==5.0.0
python-jwt==1.8.0
bcrypt==4.0.0
```

### Scaling considerations

- **Session Storage**: Redis cluster pour haute disponibilité
- **Database**: PostgreSQL avec indexes sur (user_id, app_id, session_token)
- **Caching**: Redis pour contexte session (TTL = session expiry)
- **Load Balancer**: Sticky sessions ou JWT dans Authorization header