// =========================================
// APPLICATION CONTEXT SERVICE
// =========================================

import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { BehaviorSubject, Observable, interval } from 'rxjs';
import { tap, catchError, switchMap } from 'rxjs/operators';
import { environment } from '../../environments/environment';

export interface AppContext {
  session_id: string;
  user_type: 'USER' | 'API_CLIENT' | 'ADMIN';
  accessibleApps: Array<{
    name: string;
    id?: string;
  }>;
  sessionExpiresAt: string;
  lastActivity: string;
}

@Injectable({ providedIn: 'root' })
export class ApplicationContextService {
  private contextSubject = new BehaviorSubject<AppContext | null>(null);
  public context$ = this.contextSubject.asObservable();

  private loadingSubject = new BehaviorSubject<boolean>(false);
  public loading$ = this.loadingSubject.asObservable();

  private apiBaseUrl = `${environment.apiUrl}/sessions`;
  private refreshTimerStarted = false;
  private channel: BroadcastChannel;
  private isInitializing = false;

  constructor(private http: HttpClient) {
    this.setupBroadcastChannel();
    // NE PAS charger ici, attendre le guard
  }

  // 🔑 Setup BroadcastChannel pour synchroniser entre fenêtres
  private setupBroadcastChannel(): void {
    try {
      this.channel = new BroadcastChannel('app-context');
      this.channel.onmessage = (event) => {
        if (event.data.type === 'context-updated') {
          // Une autre fenêtre a mis à jour le contexte
          this.contextSubject.next(event.data.context);
          console.log('Context synced from another window:', event.data.context);
        } else if (event.data.type === 'context-logout') {
          // Une autre fenêtre s'est logout
          this.contextSubject.next(null);
          this.refreshTimerStarted = false;
          console.log('Context cleared from logout in another window');
        }
      };
    } catch (e) {
      console.warn('BroadcastChannel not supported:', e);
    }
  }

  // 📡 Fonction PUBLIQUE : initialiser le contexte (à appeler du guard)
  initializeContext(): Observable<AppContext> {
    // ✅ Si déjà en cours d'initialisation, ne pas refaire
    if (this.isInitializing) {
      console.warn('Context initialization already in progress');
      return this.context$;
    }

    // ✅ Si contexte déjà présent, retourner directement
    if (this.contextSubject.value !== null) {
      console.log('Context already loaded');
      return this.context$;
    }

    this.isInitializing = true;
    this.loadingSubject.next(true);

    return this.loadContext().pipe(
      tap(context => {
        this.contextSubject.next(context);
        this.loadingSubject.next(false);
        this.isInitializing = false;

        // 📢 Notifier les autres fenêtres
        this.broadcastContextUpdate(context);

        // Démarrer le refresh timer APRÈS le premier chargement
        this.startRefreshTimer();
      }),
      catchError(err => {
        console.error('Failed to load context:', err);
        this.loadingSubject.next(false);
        this.isInitializing = false;
        throw err;
      })
    );
  }

  // 🔄 Charger le contexte depuis l'API
  private loadContext(): Observable<AppContext> {
    return this.http.get<AppContext>(`${this.apiBaseUrl}`, {
      withCredentials: true,
    }).pipe(
      tap(context => {
        console.log('Context loaded from API:', context);
      }),
      catchError(error => {
        console.error('Failed to load context from API:', error);
        throw error;
      })
    );
  }

  // 📢 Envoyer le contexte aux autres fenêtres via BroadcastChannel
  private broadcastContextUpdate(context: AppContext): void {
    try {
      this.channel.postMessage({
        type: 'context-updated',
        context: context,
      });
    } catch (e) {
      console.warn('Failed to broadcast context update:', e);
    }
  }

  // 🔄 Démarrer le timer de refresh (toutes les 30 min)
  private startRefreshTimer(): void {
    if (this.refreshTimerStarted) return;

    this.refreshTimerStarted = true;
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

  // ================== ACCÈS AU CONTEXTE ==================

  get currentContext(): AppContext | null {
    return this.contextSubject.value;
  }

  get allAccessibleApps(): Array<{ name: string; id?: string }> {
    return this.contextSubject.value?.accessibleApps ?? [];
  }

  get accessibleApps(): Array<{ name: string; id?: string }> {
    const apps = this.contextSubject.value?.accessibleApps ?? [];
    return apps.filter(app => app.name.toLowerCase() !== 'admin');
  }

  get hasAdminAccess(): boolean {
    const apps = this.allAccessibleApps;
    return apps.some(app => app.name.toLowerCase() === 'admin');
  }

  canAccessApp(appName: string): boolean {
    return this.allAccessibleApps.some(
      app => app.name.toLowerCase() === appName.toLowerCase()
    );
  }

  // ================== SESSION MANAGEMENT ==================

  refreshSession(): Observable<AppContext> {
    return this.http.post<AppContext>(`${this.apiBaseUrl}/refresh`, {}, {
      withCredentials: true,
    }).pipe(
      tap(context => {
        this.contextSubject.next(context);
        this.broadcastContextUpdate(context);
      }),
      catchError(error => {
        console.error('Session refresh failed:', error);
        throw error;
      })
    );
  }

  logout(): Observable<any> {
    return this.http.post(`${this.apiBaseUrl}/logout`, {}, {
      withCredentials: true,
    }).pipe(
      tap(() => {
        this.contextSubject.next(null);
        this.refreshTimerStarted = false;

        // 📢 Notifier les autres fenêtres du logout
        try {
          this.channel.postMessage({
            type: 'context-logout',
          });
        } catch (e) {
          console.warn('Failed to broadcast logout:', e);
        }
      })
    );
  }

  login(appTokens: string[]): Observable<AppContext> {
    return this.http.post<AppContext>(`${this.apiBaseUrl}/login`, { appTokens }, {
      withCredentials: true,
    }).pipe(
      tap(context => {
        this.contextSubject.next(context);
        this.broadcastContextUpdate(context);
        this.startRefreshTimer();
      }),
      catchError(error => {
        console.error('Failed to login:', error);
        throw error;
      })
    );
  }

  // ================== VÉRIFICATIONS ==================

  isSessionExpired(): boolean {
    const context = this.contextSubject.value;
    if (!context) return true;
    return new Date(context.sessionExpiresAt) < new Date();
  }

  isContextReady(): boolean {
    return this.contextSubject.value !== null;
  }

  ngOnDestroy(): void {
    if (this.channel) {
      this.channel.close();
    }
  }
}

// =========================================
// AUTH GUARD (UTILISE initializeContext())
// =========================================

import { Injectable } from '@angular/core';
import {
  CanActivate,
  ActivatedRouteSnapshot,
  Router,
  UrlTree,
} from '@angular/router';
import { Observable } from 'rxjs';
import { tap, catchError, switchMap } from 'rxjs/operators';
import { ApplicationContextService } from '../services/application-context.service';

@Injectable({ providedIn: 'root' })
export class AuthGuard implements CanActivate {
  constructor(
    private appContext: ApplicationContextService,
    private router: Router
  ) {}

  canActivate(
    route: ActivatedRouteSnapshot
  ): Observable<boolean | UrlTree> {
    // 🔑 Si contexte pas chargé, le charger
    if (!this.appContext.isContextReady()) {
      return this.appContext.initializeContext().pipe(
        switchMap(() => this.checkAuth(route)),
        catchError(() => {
          console.error('Failed to initialize context');
          return [this.router.parseUrl('/access-control')];
        })
      );
    }

    // ✅ Contexte déjà chargé, vérifier l'accès
    return this.checkAuth(route);
  }

  private checkAuth(route: ActivatedRouteSnapshot): Observable<boolean | UrlTree> {
    return new Observable(observer => {
      const context = this.appContext.currentContext;

      // ❌ Pas de contexte ou session expirée
      if (!context || this.appContext.isSessionExpired()) {
        console.warn('No context or session expired');
        observer.next(this.router.parseUrl('/access-control'));
        observer.complete();
        return;
      }

      const accessibleApps = context.accessibleApps?.map((a: any) => a.name) ?? [];

      // ❌ Pas d'apps accessibles
      if (!accessibleApps || accessibleApps.length === 0) {
        console.warn('No accessible apps');
        observer.next(this.router.parseUrl('/access-control'));
        observer.complete();
        return;
      }

      const isAdmin = accessibleApps.some(app => app.toLowerCase() === 'admin');
      const hasOtherApps = accessibleApps.length > 1;

      // 🔴 Logique: admin + autres apps → rediriger vers /admin/settings
      if (isAdmin && hasOtherApps) {
        const currentRoute = route.routeConfig?.path;
        if (currentRoute !== 'admin/settings') {
          console.warn('Admin with other apps: redirecting to admin/settings');
          observer.next(this.router.parseUrl('/admin/settings'));
          observer.complete();
          return;
        }
      }

      // ✅ Vérifier l'accès à une app spécifique
      const appName = route.params['appName'];
      if (appName) {
        const hasAccess = accessibleApps.some(
          app => app.toLowerCase() === appName.toLowerCase()
        );
        if (!hasAccess) {
          console.warn(`No access to app: ${appName}`);
          observer.next(this.router.parseUrl('/access-control'));
          observer.complete();
          return;
        }
      }

      // ✅ Tous les contrôles passent
      observer.next(true);
      observer.complete();
    });
  }
}

// =========================================
// SSO GUARD (MINIMAL)
// =========================================

import { Injectable } from '@angular/core';
import { CanActivate, ActivatedRouteSnapshot, Router, UrlTree } from '@angular/router';
import { OAuthService } from 'angular-oauth2-oidc';

@Injectable({ providedIn: 'root' })
export class sSOGuard implements CanActivate {
  constructor(
    private oauthService: OAuthService,
    private router: Router
  ) {}

  canActivate(): boolean | UrlTree {
    if (this.oauthService.hasValidAccessToken()) {
      return true;
    }
    return this.router.parseUrl('/auth');
  }
}