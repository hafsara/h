// =========================================
// 1️⃣ APPLICATION CONTEXT SERVICE (CORRIGÉ)
// =========================================

import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { BehaviorSubject, Observable, interval, firstValueFrom } from 'rxjs';
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

  private loadingSubject = new BehaviorSubject<boolean>(true);
  public loading$ = this.loadingSubject.asObservable();

  private apiBaseUrl = `${environment.apiUrl}/sessions`;
  private refreshTimerStarted = false;

  constructor(private http: HttpClient) {
    // ✅ Charger le contexte UNE SEULE FOIS au démarrage
    this.initializeContext();
  }

  // 🔑 Initialiser le contexte (appelé une fois au démarrage)
  private initializeContext(): void {
    this.loadContext().subscribe({
      next: (context) => {
        this.contextSubject.next(context);
        this.loadingSubject.next(false);
        // Démarrer le refresh timer APRÈS le premier chargement
        this.startRefreshTimer();
      },
      error: (err) => {
        console.error('Failed to load context:', err);
        this.loadingSubject.next(false);
        // Même en erreur, démarrer le timer (pour retry)
        this.startRefreshTimer();
      },
    });
  }

  // 📡 Charger le contexte depuis l'API
  private loadContext(): Observable<AppContext> {
    return this.http.get<AppContext>(`${this.apiBaseUrl}`, {
      withCredentials: true,
    }).pipe(
      tap(context => {
        console.log('Context loaded:', context);
      }),
      catchError(error => {
        console.error('Failed to load context:', error);
        throw error;
      })
    );
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
    // Filtrer les apps admin
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
      })
    );
  }

  login(appTokens: string[]): Observable<AppContext> {
    return this.http.post<AppContext>(`${this.apiBaseUrl}/login`, { appTokens }, {
      withCredentials: true,
    }).pipe(
      tap(context => {
        this.contextSubject.next(context);
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

  // Attendre que le contexte soit chargé (utile pour les guards)
  waitForContext(): Promise<AppContext | null> {
    return new Promise((resolve) => {
      const subscription = this.context$.subscribe(context => {
        if (context !== null) {
          subscription.unsubscribe();
          resolve(context);
        }
      });

      // Timeout après 5 secondes
      setTimeout(() => {
        subscription.unsubscribe();
        resolve(this.currentContext);
      }, 5000);
    });
  }
}

// =========================================
// 2️⃣ AUTH GUARD (CORRIGÉ & OPTIMISÉ)
// =========================================

import { Injectable } from '@angular/core';
import {
  CanActivate,
  ActivatedRouteSnapshot,
  Router,
  UrlTree,
} from '@angular/router';
import { Observable, of } from 'rxjs';
import { switchMap, take } from 'rxjs/operators';
import { ApplicationContextService } from '../services/application-context.service';

@Injectable({ providedIn: 'root' })
export class AuthGuard implements CanActivate {
  constructor(
    private appContext: ApplicationContextService,
    private router: Router
  ) {}

  canActivate(
    route: ActivatedRouteSnapshot
  ): boolean | UrlTree | Observable<boolean | UrlTree> | Promise<boolean | UrlTree> {
    // 🔑 Attendre que le contexte soit chargé
    return this.checkAuth(route);
  }

  private async checkAuth(route: ActivatedRouteSnapshot): Promise<boolean | UrlTree> {
    // Attendre que le contexte soit dispo
    const context = await this.appContext.waitForContext();

    // ❌ Pas de contexte ou session expirée
    if (!context || this.appContext.isSessionExpired()) {
      console.warn('No context or session expired');
      return this.router.parseUrl('/access-control');
    }

    const accessibleApps = context.accessibleApps?.map((a: any) => a.name) ?? [];

    // ❌ Pas d'apps accessibles
    if (!accessibleApps || accessibleApps.length === 0) {
      console.warn('No accessible apps');
      return this.router.parseUrl('/access-control');
    }

    const isAdmin = accessibleApps.some(app => app.toLowerCase() === 'admin');
    const hasOtherApps = accessibleApps.length > 1;

    // 🔴 Logique spéciale: admin + autres apps → rediriger vers /admin/settings
    if (isAdmin && hasOtherApps) {
      const currentRoute = route.routeConfig?.path;
      if (currentRoute !== 'admin/settings') {
        console.warn('Admin with other apps: redirecting to admin/settings');
        return this.router.parseUrl('/admin/settings');
      }
    }

    // ✅ Vérifier l'accès à une app spécifique si présente dans la route
    const appName = route.params['appName'];
    if (appName) {
      const hasAccess = accessibleApps.some(
        app => app.toLowerCase() === appName.toLowerCase()
      );
      if (!hasAccess) {
        console.warn(`No access to app: ${appName}`);
        return this.router.parseUrl('/access-control');
      }
    }

    // ✅ Tous les contrôles passent
    return true;
  }
}

// =========================================
// 3️⃣ SSO GUARD (EXEMPLE)
// =========================================

import { Injectable } from '@angular/core';
import { CanActivate, ActivatedRouteSnapshot, Router, UrlTree } from '@angular/router';
import { Observable } from 'rxjs';
import { OAuthService } from 'angular-oauth2-oidc';

@Injectable({ providedIn: 'root' })
export class sSOGuard implements CanActivate {
  constructor(
    private oauthService: OAuthService,
    private router: Router
  ) {}

  canActivate(
    route: ActivatedRouteSnapshot
  ): boolean | UrlTree | Observable<boolean | UrlTree> | Promise<boolean | UrlTree> {
    // Vérifier que l'utilisateur a un token valide
    if (this.oauthService.hasValidAccessToken()) {
      return true;
    }

    // Sinon rediriger vers login
    return this.router.parseUrl('/auth');
  }
}

// =========================================
// 4️⃣ APP.MODULE.TS (MINIMAL)
// =========================================

import { NgModule, APP_INITIALIZER } from '@angular/core';
import { BrowserModule } from '@angular/platform-browser';
import { HttpClientModule, HTTP_INTERCEPTORS } from '@angular/common/http';
import { OAuthModule } from 'angular-oauth2-oidc';

import { AppComponent } from './app.component';
import { DarkModeService } from './services/navbar/dark-mode.service';
import { AuthInitService } from './services/auth-init.service';
import { AuthInterceptor } from './interceptors/auth.interceptor';
import { AuthGuard } from './guards/auth.guard';
import { sSOGuard } from './guards/sso.guard';

export function initializeDarkMode(darkMode: DarkModeService) {
  return () => darkMode.initializeOnStartup();
}

export function initializeAuth(authService: AuthInitService) {
  return () => authService.initializeAuth();
}

@NgModule({
  declarations: [AppComponent],
  imports: [
    BrowserModule,
    HttpClientModule,
    OAuthModule.forRoot(),
  ],
  providers: [
    {
      provide: APP_INITIALIZER,
      useFactory: initializeDarkMode,
      deps: [DarkModeService],
      multi: true,
    },
    {
      provide: APP_INITIALIZER,
      useFactory: initializeAuth,
      deps: [AuthInitService],
      multi: true,
    },
    {
      provide: HTTP_INTERCEPTORS,
      useClass: AuthInterceptor,
      multi: true,
    },
    AuthGuard,
    sSOGuard,
  ],
  bootstrap: [AppComponent],
})
export class AppModule {}