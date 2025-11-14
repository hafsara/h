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

## ✅ Backend (Python)

1. **Remplacer** `/presence/{access_token}/stream` (SSE) par `/presence/{access_token}/viewers` (GET - polling)
2. **Augmenter** TTL de 20s à 35s
3. **Ajouter** endpoint `/app/{app_id}/status` pour détection changements d'app

## ✅ Frontend (Angular)

1. **Remplacer PresenceService** → polling au lieu de SSE
2. **Ajouter AppInvalidationService** → détecte les changements d'app
3. **Dans les components** :
   - Appeler `startHeartbeat()` et `startViewersPolling()`
   - S'abonner aux viewers
   - Ajouter détection d'invalidation d'app

## 🎯 Flux

```
Frontend:
- Toutes les 1.5s : POST /presence/{token} (heartbeat)
- Toutes les 1.5s : GET /presence/{token}/viewers (polling viewers)
- Toutes les 5s : GET /app/{id}/status (polling app invalidation)

Backend:
- Redis auto-expire les clés après 35s (si pas de heartbeat)
- Version hash change = app modifiée = session invalidée
```

C'est **beaucoup plus simple** que SSE et **Apigee-friendly** ! 🚀
# ============================================================
# BACKEND - presence_bp.py
# Remplacer le code existant par celui-ci
# ============================================================

from flask import Blueprint, request, jsonify
from api.extensions import redis_client
from api.helpers.tools import error_response
from api.routes.auth_decorators import require_user_token
import json

presence_bp = Blueprint("presence_bp", __name__)
TTL_SECONDS = 35  # Augmenté de 20 à 35 pour plus stable

# =====================================================
# 1. UPDATE PRESENCE (Heartbeat)
# =====================================================

@presence_bp.route("/presence/<string:access_token>", methods=["POST"])
@require_user_token
def register_presence(access_token):
    """
    Met à jour la présence d'un utilisateur.
    À appeler toutes les 1.5-2s du frontend (heartbeat).
    
    Le TTL auto-expire après 35s si pas de heartbeat.
    """
    data = request.json or {}
    uid = getattr(request, 'user_id', None)
    username = data.get("username")

    if not uid or not username:
        return error_response("User info missing", 400)

    # Clé Redis : presence:{access_token}:{uid}
    # Valeur : username (+ timestamp optionnel)
    key = f"presence:{access_token}:{uid}"
    
    viewer_data = json.dumps({
        'uid': uid,
        'username': username,
        'timestamp': request.headers.get('X-Request-Time', '')
    })
    
    # Stocker avec TTL auto-expire
    redis_client.setex(key, TTL_SECONDS, viewer_data)
    
    return jsonify({"message": "Presence updated", "ttl": TTL_SECONDS}), 200


# =====================================================
# 2. GET VIEWERS (Polling endpoint)
# =====================================================

@presence_bp.route("/presence/<string:access_token>/viewers", methods=["GET"])
@require_user_token
def get_viewers(access_token):
    """
    Retourne la liste des viewers actuels pour un accès token.
    À appeler en polling depuis Angular (toutes les 1.5-2s).
    
    Ne retourne pas l'utilisateur courant.
    """
    uid = getattr(request, 'user_id', None)
    
    # Récupérer toutes les clés presence:{access_token}:*
    pattern = f"presence:{access_token}:*"
    keys = redis_client.keys(pattern)
    
    viewers = []
    for key in keys:
        try:
            data = redis_client.get(key)
            if data:
                viewer = json.loads(data)
                # Exclure l'utilisateur courant
                if viewer['uid'] != uid:
                    viewers.append({
                        'uid': viewer['uid'],
                        'username': viewer['username']
                    })
        except (json.JSONDecodeError, KeyError):
            continue
    
    return jsonify({
        "success": True,
        "viewers": viewers,
        "count": len(viewers)
    }), 200


# =====================================================
# 3. CLEANUP (Optional - pour admin)
# =====================================================

@presence_bp.route("/presence/cleanup/<string:access_token>", methods=["POST"])
@require_user_token
def cleanup_presence(access_token):
    """
    Nettoie manuellement les clés expirées (optionnel).
    Redis le fait auto avec TTL, mais peut être utile pour debug.
    """
    pattern = f"presence:{access_token}:*"
    keys = redis_client.keys(pattern)
    
    cleaned = 0
    for key in keys:
        if redis_client.exists(key):
            # Vérifier si expiré
            ttl = redis_client.ttl(key)
            if ttl == -2:  # Key doesn't exist
                cleaned += 1
    
    return jsonify({
        "success": True,
        "message": f"Cleaned {cleaned} expired keys"
    }), 200// ============================================================
// SERVICE - presence.service.ts
// Remplacer le service existant par celui-ci
// ============================================================

import { Injectable, OnDestroy } from '@angular/core';
import { HttpClient, HttpHeaders } from '@angular/common/http';
import { Observable, BehaviorSubject, interval, Subscription } from 'rxjs';
import { switchMap, tap, catchError, startWith } from 'rxjs/operators';
import { environment } from '../../environments/environment';
import { SharedService } from './shared.service';

export interface Viewer {
  uid: string;
  username: string;
}

@Injectable({ providedIn: 'root' })
export class PresenceService implements OnDestroy {
  private apiUrl = `${environment.apiUrl}/presence`;
  
  private viewers$ = new BehaviorSubject<Viewer[]>([]);
  private pollingSubscription?: Subscription;
  private heartbeatSubscription?: Subscription;
  
  private pollInterval = 1500; // ms
  private heartbeatInterval = 1500; // ms

  constructor(
    private http: HttpClient,
    private sharedService: SharedService
  ) {}

  private getHeaders(): HttpHeaders {
    const token = localStorage.getItem('sso_token') || '';
    return new HttpHeaders({
      Authorization: `Bearer ${token}`,
      'X-Request-Time': new Date().toISOString()
    });
  }

  /**
   * Démarre le heartbeat (mise à jour de présence).
   * À appeler au chargement du formulaire.
   */
  startHeartbeat(accessToken: string): void {
    this.stopHeartbeat();

    this.heartbeatSubscription = interval(this.heartbeatInterval)
      .pipe(
        startWith(0), // Appeler immédiatement
        switchMap(() => this.updatePresenceRequest(accessToken)),
        catchError(error => {
          console.error('Heartbeat error:', error);
          return [];
        })
      )
      .subscribe();
  }

  /**
   * Arrête le heartbeat.
   */
  stopHeartbeat(): void {
    if (this.heartbeatSubscription) {
      this.heartbeatSubscription.unsubscribe();
    }
  }

  /**
   * Démarre le polling des viewers.
   * À appeler au chargement du formulaire.
   */
  startViewersPolling(accessToken: string): void {
    this.stopViewersPolling();

    this.pollingSubscription = interval(this.pollInterval)
      .pipe(
        startWith(0), // Appeler immédiatement
        switchMap(() => this.getViewersRequest(accessToken)),
        tap(response => {
          if (response.success) {
            this.viewers$.next(response.viewers);
          }
        }),
        catchError(error => {
          console.error('Viewers polling error:', error);
          if (error.status === 401 || error.status === 403) {
            console.warn('Session invalid - redirecting');
            window.location.href = '/login';
          }
          return [];
        })
      )
      .subscribe();
  }

  /**
   * Arrête le polling des viewers.
   */
  stopViewersPolling(): void {
    if (this.pollingSubscription) {
      this.pollingSubscription.unsubscribe();
    }
  }

  /**
   * Requête HTTP - Update presence
   */
  private updatePresenceRequest(accessToken: string): Observable<any> {
    const user = this.sharedService.getUserInfo();
    
    return this.http.post(
      `${this.apiUrl}/${accessToken}`,
      {
        username: user.username
      },
      { headers: this.getHeaders() }
    );
  }

  /**
   * Requête HTTP - Get viewers
   */
  private getViewersRequest(accessToken: string): Observable<any> {
    return this.http.get<any>(
      `${this.apiUrl}/${accessToken}/viewers`,
      { headers: this.getHeaders() }
    );
  }

  /**
   * Observable des viewers
   */
  getViewers(): Observable<Viewer[]> {
    return this.viewers$.asObservable();
  }

  /**
   * Récupère les viewers courants (snapshot)
   */
  getCurrentViewers(): Viewer[] {
    return this.viewers$.value;
  }

  ngOnDestroy(): void {
    this.stopHeartbeat();
    this.stopViewersPolling();
  }
}


// ============================================================
// COMPONENT - draft-form-editor.component.ts
// Remplacer par celui-ci (simplifié)
// ============================================================

import { Component, OnInit, OnDestroy } from '@angular/core';
import { ActivatedRoute, Router } from '@angular/router';
import { FormService } from '../../services/form.service';
import { PresenceService, Viewer } from '../../services/presence.service';
import { SharedService } from '../../services/shared.service';
import { MessageService, ConfirmationService } from 'primeng/api';
import { formatQuestions } from '../../utils/question-formatter';
import { environment } from '../../../environments/environment';
import { Observable, Subject } from 'rxjs';
import { takeUntil } from 'rxjs/operators';

@Component({
  selector: 'app-draft-form-editor',
  templateUrl: './draft-form-editor.component.html',
  styleUrls: ['./draft-form-editor.component.scss']
})
export class DraftFormEditorComponent implements OnInit, OnDestroy {
  formData: any = { forms: [] };
  currentForm: any;
  markdownDescription: string = '';
  accessToken: string = '';
  
  questionDialogVisible = false;
  editingQuestion: any = {};
  editingIndex: number = -1;
  editingTitle: boolean = false;
  editingUser: boolean = false;
  editingDescription: boolean = false;
  showErrors: boolean = true;
  invalidCcEmail: boolean = false;

  emailPattern = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
  emailKeywords = environment.emailKeywords;

  // Présence
  viewers$: Observable<Viewer[]>;
  viewers: Viewer[] = [];
  flashBg: boolean = false;

  private destroy$ = new Subject<void>();

  constructor(
    private route: ActivatedRoute,
    private formService: FormService,
    private presenceService: PresenceService,
    private sharedService: SharedService,
    private messageService: MessageService,
    private confirmationService: ConfirmationService,
    private router: Router
  ) {
    this.viewers$ = this.presenceService.getViewers();
  }

  ngOnInit(): void {
    this.accessToken = this.route.snapshot.paramMap.get('access_token') || '';
    if (!this.accessToken) {
      this.router.navigate(['/404']);
      return;
    }

    this.loadDraft();

    // ===== PRÉSENCE =====
    // 1. Démarrer le heartbeat (envoyer notre présence toutes les 1.5s)
    this.presenceService.startHeartbeat(this.accessToken);

    // 2. Démarrer le polling des viewers (récupérer les autres toutes les 1.5s)
    this.presenceService.startViewersPolling(this.accessToken);

    // 3. S'abonner aux changements de viewers
    this.viewers$
      .pipe(takeUntil(this.destroy$))
      .subscribe(viewers => {
        const previousCount = this.viewers.length;
        this.viewers = viewers;

        // Flash si nouveau viewer arrive
        if (viewers.length > previousCount) {
          this.flashBg = true;
          setTimeout(() => this.flashBg = false, 2000);
        }
      });
  }

  private loadDraft(): void {
    this.formService.getFormContainerByAccessToken(this.accessToken)
      .pipe(takeUntil(this.destroy$))
      .subscribe({
        next: data => {
          this.formData = data;
          this.markdownDescription = this.formData.description.replace(/\\n/g, '\n');
          this.formData.access_token = this.accessToken;
          this.currentForm = this.formData.forms[0];
          if (this.currentForm) {
            this.currentForm.questions = formatQuestions(this.currentForm.questions);
          }
        },
        error: () => this.router.navigate(['/404'])
      });
  }

  toggleEditTitle(): void {
    if (this.editingTitle && this.isValidDraft()) {
      this.saveDraft();
    }
    this.editingTitle = !this.editingTitle;
  }

  toggleEditUser(): void {
    if (this.editingUser && this.isValidDraft()) {
      this.saveDraft();
    }
    this.editingUser = !this.editingUser;
  }

  toggleEditDescription(): void {
    if (this.editingDescription && this.isValidDraft()) {
      this.saveDraft();
    }
    this.editingDescription = !this.editingDescription;
  }

  confirmSaveDraft(): void {
    this.showErrors = true;
    if (!this.isValidDraft()) {
      this.messageService.add({
        severity: 'error',
        summary: 'Validation failed',
        detail: 'Please correct the errors.'
      });
      return;
    }
    this.saveDraft();
  }

  confirmSubmitDraft(): void {
    this.showErrors = true;
    if (!this.isValidDraft()) {
      this.messageService.add({
        severity: 'error',
        summary: 'Validation failed',
        detail: 'Please correct the errors.'
      });
      return;
    }

    this.confirmationService.confirm({
      message: 'Are you sure you want to submit this draft? You will not be able to edit it afterward.',
      header: 'Confirm Submit',
      icon: 'pi pi-exclamation-triangle',
      accept: () => this.saveDraft(true)
    });
  }

  saveDraft(submit: boolean = false): void {
    const payload = {
      title: this.formData.title,
      description: this.formData.description,
      user_email: this.formData.user_email,
      escalade_email: this.formData.escalade_email,
      cc_emails: this.formData.cc_emails,
      questions: this.currentForm.questions,
      submit
    };

    this.formService.updateDraft(this.accessToken, payload)
      .pipe(takeUntil(this.destroy$))
      .subscribe({
        next: () => {
          this.messageService.add({
            severity: 'contrast',
            summary: submit ? 'Draft submitted' : 'Draft saved'
          });
          if (submit) {
            setTimeout(() => window.location.reload(), 1000);
          }
        },
        error: () => {
          this.messageService.add({
            severity: 'error',
            summary: 'Error',
            detail: 'Failed to save draft'
          });
        }
      });
  }

  isValidDraft(): boolean {
    const validTitle = this.formData.title?.trim() !== '';
    const validDescription = this.formData.description?.trim() !== '';
    const validUserEmail = this.emailPattern.test(this.formData.user_email || '');
    const validEscalationEmail = !this.formData.escalade_email || this.emailPattern.test(this.formData.escalade_email);
    const validCcEmails = !this.formData.cc_emails || this.formData.cc_emails.length === 0 ||
      this.formData.cc_emails.every((email: string) =>
        this.emailPattern.test(email) || this.emailKeywords.includes(email.toUpperCase())
      );
    this.invalidCcEmail = !validCcEmails;

    return validTitle && validDescription && validUserEmail && validEscalationEmail && validCcEmails;
  }

  onCcEmailAdd(event: any): void {
    this.invalidCcEmail = !this.formData.cc_emails.every((email: string) =>
      this.emailPattern.test(email) || this.emailKeywords.includes(email.toUpperCase())
    );
  }

  onCcEmailRemove(event: any): void {
    this.invalidCcEmail = false;
  }

  ngOnDestroy(): void {
    this.presenceService.stopHeartbeat();
    this.presenceService.stopViewersPolling();
    this.destroy$.next();
    this.destroy$.complete();
  }
}


// ============================================================
// COMPONENT - form-container-preview.component.ts
// Ajouter la présence au component existant (résumé)
// ============================================================

// Dans le ngOnInit():
ngOnInit(): void {
  this.accessToken = this.accessToken || this.route.snapshot.paramMap.get('access_token') || '';
  this.loadFormContainer();
  this.startPolling();

  // ===== PRÉSENCE =====
  this.presenceService.startHeartbeat(this.accessToken);
  this.presenceService.startViewersPolling(this.accessToken);

  this.presenceService.getViewers()
    .pipe(takeUntil(this.destroy$))
    .subscribe(viewers => {
      const previousCount = this.viewers.length;
      this.viewers = viewers;

      if (viewers.length > previousCount) {
        this.flashBg = true;
        setTimeout(() => this.flashBg = false, 2000);
      }
    });
}

// Dans le ngOnDestroy():
ngOnDestroy(): void {
  this.presenceService.stopHeartbeat();
  this.presenceService.stopViewersPolling();
  // ... rest of cleanup
}// ============================================================
// SERVICE - app-invalidation.service.ts (NOUVEAU)
// Pour détecter les changements d'app
// ============================================================

import { Injectable, OnDestroy } from '@angular/core';
import { HttpClient, HttpHeaders } from '@angular/common/http';
import { BehaviorSubject, Observable, interval, Subscription } from 'rxjs';
import { switchMap, tap, catchError } from 'rxjs/operators';
import { environment } from '../../environments/environment';

export interface AppStatus {
  app_id: string;
  is_active: boolean;
  version_hash: string;
  last_check: Date;
}

@Injectable({ providedIn: 'root' })
export class AppInvalidationService implements OnDestroy {
  private apiUrl = `${environment.apiUrl}/app`;
  
  private appStatus$ = new BehaviorSubject<AppStatus | null>(null);
  private isInvalidated$ = new BehaviorSubject<boolean>(false);
  private pollingSubscription?: Subscription;
  
  private pollInterval = 5000; // 5 secondes (moins fréquent que présence)

  constructor(private http: HttpClient) {}

  private getHeaders(): HttpHeaders {
    const token = localStorage.getItem('sso_token') || '';
    return new HttpHeaders({
      Authorization: `Bearer ${token}`
    });
  }

  /**
   * Démarre le polling du statut de l'app.
   * À appeler au chargement des pages principales.
   */
  startAppPolling(appId: string): void {
    this.stopAppPolling();

    this.pollingSubscription = interval(this.pollInterval)
      .pipe(
        switchMap(() => this.checkAppStatus(appId)),
        tap(response => {
          if (response.success) {
            // Récupérer le status
            const newStatus: AppStatus = {
              app_id: appId,
              is_active: response.is_active,
              version_hash: response.version_hash,
              last_check: new Date()
            };

            const previousStatus = this.appStatus$.value;

            // Détecter un changement
            if (previousStatus && previousStatus.version_hash !== newStatus.version_hash) {
              console.warn('App version changed - session will be invalidated');
              this.isInvalidated$.next(true);
            }

            // Détecter une désactivation
            if (previousStatus && previousStatus.is_active && !newStatus.is_active) {
              console.warn('App has been deactivated');
              this.isInvalidated$.next(true);
            }

            this.appStatus$.next(newStatus);
          }
        }),
        catchError(error => {
          console.error('App polling error:', error);
          if (error.status === 401 || error.status === 403) {
            // Session invalide
            this.isInvalidated$.next(true);
          }
          return [];
        })
      )
      .subscribe();
  }

  /**
   * Arrête le polling
   */
  stopAppPolling(): void {
    if (this.pollingSubscription) {
      this.pollingSubscription.unsubscribe();
    }
  }

  /**
   * Requête HTTP - Check app status
   */
  private checkAppStatus(appId: string): Observable<any> {
    return this.http.get<any>(
      `${this.apiUrl}/${appId}/status`,
      { headers: this.getHeaders() }
    );
  }

  /**
   * Observable du statut de l'app
   */
  getAppStatus(): Observable<AppStatus | null> {
    return this.appStatus$.asObservable();
  }

  /**
   * Observable : est-ce que la session a été invalidée?
   */
  getInvalidated(): Observable<boolean> {
    return this.isInvalidated$.asObservable();
  }

  /**
   * Récupérer l'état actuel
   */
  isCurrentlyInvalidated(): boolean {
    return this.isInvalidated$.value;
  }

  ngOnDestroy(): void {
    this.stopAppPolling();
  }
}


// ============================================================
// BACKEND - Ajouter à presence_bp.py (ou app_bp.py)
// ============================================================

"""
from flask import Blueprint, request, jsonify
from api.extensions import redis_client
from api.routes.auth_decorators import require_user_token
from datetime import datetime
import hashlib
import json

app_bp = Blueprint("app_bp", __name__)

# =====================================================
# CHECK APP STATUS (pour polling)
# =====================================================

@app_bp.route("/app/<string:app_id>/status", methods=["GET"])
@require_user_token
def check_app_status(app_id):
    '''
    Endpoint pour vérifier le statut de l'app.
    Angular poll ça toutes les 5s.
    
    Retourne:
    - is_active: boolean (app active ou pas)
    - version_hash: string (hash de la config de l'app)
    '''
    from models import ApplicationMetadata, ApplicationSession
    
    uid = getattr(request, 'user_id', None)
    
    # Récupérer la session courante
    session_token = request.cookies.get('session_token')
    session = ApplicationSession.query.filter_by(
        session_token=session_token,
        is_active=True
    ).first()
    
    if not session:
        return jsonify({'error': 'Session not found'}), 401
    
    # Vérifier accès à l'app
    if app_id not in session.accessible_apps:
        return jsonify({'error': 'App not accessible'}), 403
    
    # Récupérer l'app
    app = ApplicationMetadata.query.filter_by(app_id=app_id).first()
    if not app:
        return jsonify({'error': 'App not found'}), 404
    
    # Calculer le version hash
    version_data = {
        'app_id': app.app_id,
        'name': app.name,
        'available_roles': app.available_roles,
        'is_active': app.is_active,
        'updated_at': app.updated_at.isoformat() if hasattr(app, 'updated_at') else ''
    }
    version_str = json.dumps(version_data, sort_keys=True, default=str)
    version_hash = hashlib.sha256(version_str.encode()).hexdigest()
    
    return jsonify({
        'success': True,
        'app_id': app_id,
        'is_active': app.is_active,
        'version_hash': version_hash,
        'timestamp': datetime.utcnow().isoformat()
    }), 200
"""


// ============================================================
// COMPONENT - navbar.component.ts (Ajouter app detection)
// ============================================================

import { AppInvalidationService } from '../../services/app-invalidation.service';

export class NavbarComponent implements OnInit, OnDestroy {
  // ... existing code ...

  constructor(
    private tokenService: TokenService,
    private sharedService: SharedService,
    private router: Router,
    private messageService: MessageService,
    private appSelection: AppSelectionService,
    private appInvalidation: AppInvalidationService,  // ← AJOUTER
    // ... other services ...
  ) {}

  ngOnInit() {
    // ... existing code ...

    // ===== AJOUTER : Polling du statut de l'app =====
    const appIds = this.appSelection.getDecodedAppIds();
    if (appIds.length > 0) {
      const primaryAppId = appIds[0];
      this.appInvalidation.startAppPolling(primaryAppId);

      // S'abonner aux invalidations
      this.appInvalidation.getInvalidated()
        .pipe(takeUntil(this.destroy$))
        .subscribe(isInvalidated => {
          if (isInvalidated) {
            this.handleAppInvalidation();
          }
        });
    }
  }

  private handleAppInvalidation(): void {
    this.messageService.add({
      severity: 'error',
      summary: 'Session Invalidated',
      detail: 'Application was updated or your session expired. Redirecting to login...',
      key: 'app-invalidation',
      life: 5000
    });

    setTimeout(() => {
      this.logout();
    }, 3000);
  }

  ngOnDestroy(): void {
    this.appInvalidation.stopAppPolling();
    // ... rest of cleanup ...
  }
}


// ============================================================
// COMPONENT - form-container-preview.component.ts
// Ajouter détection app invalidation
// ============================================================

export class FormContainerPreviewComponent implements OnInit, OnDestroy {
  // ... existing code ...

  constructor(
    private formService: FormService,
    private presenceService: PresenceService,
    private appInvalidation: AppInvalidationService,  // ← AJOUTER
    private messageService: MessageService,
    private router: Router,
    // ... other services ...
  ) {}

  ngOnInit(): void {
    this.accessToken = this.accessToken || this.route.snapshot.paramMap.get('access_token') || '';
    this.loadFormContainer();
    this.startPolling();

    // ===== PRÉSENCE =====
    this.presenceService.startHeartbeat(this.accessToken);
    this.presenceService.startViewersPolling(this.accessToken);

    // ===== AJOUTER : Détecter changements d'app =====
    const appId = this.sharedService.getCurrentAppId() || 'default-app';
    this.appInvalidation.startAppPolling(appId);

    this.appInvalidation.getInvalidated()
      .pipe(takeUntil(this.destroy$))
      .subscribe(isInvalidated => {
        if (isInvalidated) {
          this.messageService.add({
            severity: 'error',
            summary: 'Form Unavailable',
            detail: 'The application was updated. Redirecting...',
            key: 'form-invalidation'
          });
          setTimeout(() => this.router.navigate(['/dashboard']), 2000);
        }
      });
  }

  ngOnDestroy(): void {
    this.presenceService.stopHeartbeat();
    this.presenceService.stopViewersPolling();
    this.appInvalidation.stopAppPolling();  // ← AJOUTER
    // ... rest of cleanup ...
  }
}