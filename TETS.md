Voici **la vraie solution propre, robuste et Angular-friendly** pour **résoudre tes deux problèmes** :

---

# ✅ **1) Problème du DarkMode : il doit être initialisé AVANT toute fenêtre et partagé instantanément partout**

Actuellement :

* Le `DarkModeService` fonctionne, **mais il ne se déclenche qu'au moment où les composants s'affichent**.
* Tu veux que :
  ✔️ le thème soit appliqué **dès le bootstrap de l'application Angular**
  ✔️ toutes les fenêtres (même autres onglets) soient **synchronisées immédiatement**

### ✅ **Solution complète**

### **A. Initialiser le thème AVANT Angular : via `APP_INITIALIZER`**

👉 Ajoute ceci dans `app.module.ts` :

```ts
import { APP_INITIALIZER, NgModule } from '@angular/core';
import { DarkModeService } from './services/navbar/dark-mode.service';

export function initDarkMode(darkMode: DarkModeService) {
  return () => darkMode.initializeOnStartup();
}

@NgModule({
  providers: [
    DarkModeService,
    {
      provide: APP_INITIALIZER,
      useFactory: initDarkMode,
      deps: [DarkModeService],
      multi: true
    }
  ]
})
export class AppModule {}
```

### **B. Ajoute une méthode spéciale dans `DarkModeService`**

```ts
initializeOnStartup() {
  const mode = this.getInitialMode();
  this.applyDarkMode(mode);
}
```

### Résultat

✔️ Le mode sombre est appliqué **avant le rendu Angular**
✔️ Aucun flash blanc
✔️ Toutes les fenêtres Angular reçoivent la bonne valeur immédiatement

---

# ✅ **2) Synchroniser le DarkMode entre plusieurs fenêtres**

Toujours dans `DarkModeService` :

```ts
private channel = new BroadcastChannel('dark-mode');

constructor() {
  this.channel.onmessage = (event) => {
    this.isDarkModeSubject.next(event.data);
    this.applyDarkMode(event.data);
  };
}

toggleDarkMode(): void {
  const newMode = !this.isDarkModeSubject.value;

  this.isDarkModeSubject.next(newMode);
  localStorage.setItem('darkMode', JSON.stringify(newMode));
  
  this.applyDarkMode(newMode);

  this.channel.postMessage(newMode);
}
```

### Résultat

✔️ Si tu changes le mode sombre dans un onglet → tous les onglets changent **instantanément**
✔️ Pas besoin de refresh
✔️ Architecture propre

---

# ✅ **3) PROBLÈME AUTH (OAUTH2) : première requête qui foire car le token / user_id ne sont pas encore chargés**

C’est un problème TRÈS classique avec `angular-oauth2-oidc`.

La solution Angular officielle :

👉 **Utiliser `APP_INITIALIZER` pour attendre le chargement du token AVANT bootstrap**
👉 Injecter ce token dans ton interceptor **uniquement après initialisation**

---

# 🟦 **A. APP_INITIALIZER pour OAuth**

Dans `app.module.ts` :

```ts
export function authInitializer(oauthService: OAuthService) {
  return () =>
    oauthService.loadDiscoveryDocumentAndTryLogin().then(() => {
      return oauthService.loadUserProfile();
    });
}

providers: [
  {
    provide: APP_INITIALIZER,
    useFactory: authInitializer,
    deps: [OAuthService],
    multi: true
  }
]
```

---

# 🟦 **B. Interceptor CORRECT**

Ton interceptor doit attendre que l’OAuthService soit prêt :

```ts
intercept(req: HttpRequest<any>, next: HttpHandler) {
  const token = this.oauthService.getAccessToken();
  const userId = this.oauthService.getIdentityClaims()?.sub;

  const authReq = req.clone({
    setHeaders: {
      Authorization: token ? `Bearer ${token}` : '',
      'X-User-Id': userId || '',
    },
  });

  return next.handle(authReq);
}
```

### Résultat

✔️ **La première requête contient le token et le user_id**
✔️ Plus aucune erreur « undefined token »
✔️ Tout fonctionne même après refresh

---

# 🎯 Résumé final

Tu dois appliquer 2 patterns :

---

## 🎉 **✔️ Pour le DarkMode**

* Charger le thème AVANT Angular (`APP_INITIALIZER`)
* Synchroniser plusieurs onglets (`BroadcastChannel`)
* Mettre à jour le menu dès le changement

---

## 🎉 **✔️ Pour l'OAuth**

* Charger `loadDiscoveryDocumentAndTryLogin()` AVANT le bootstrap Angular
* TOUTE ta logique auth est prête avant la première requête HTTP
* L’interceptor fonctionne dès la première milliseconde

---

# Si tu veux, je peux te générer :

✅ la version finale de `dark-mode.service.ts`
✅ la version finale de `auth.service.ts`
✅ toute la configuration `app.module.ts` prête à coller

Souhaites-tu que je te donne les **fichiers complets** ?









# CLAUDE
// =========================================
// 1️⃣ DARK MODE SERVICE (FINAL & OPTIMISÉ)
// =========================================

import { Injectable } from '@angular/core';
import { BehaviorSubject, Observable } from 'rxjs';

@Injectable({
  providedIn: 'root'
})
export class DarkModeService {
  private isDarkModeSubject = new BehaviorSubject<boolean>(this.getInitialMode());
  isDarkMode$: Observable<boolean> = this.isDarkModeSubject.asObservable();
  private channel = new BroadcastChannel('dark-mode');

  constructor() {
    // Écouter les changements des autres tabs/fenêtres
    this.channel.onmessage = (event) => {
      this.isDarkModeSubject.next(event.data);
      this.applyDarkMode(event.data);
    };
  }

  // 🔑 Appelé par APP_INITIALIZER AVANT le bootstrap
  initializeOnStartup(): void {
    const mode = this.getInitialMode();
    this.isDarkModeSubject.next(mode);
    this.applyDarkMode(mode);
  }

  toggleDarkMode(): void {
    const newMode = !this.isDarkModeSubject.value;
    
    this.isDarkModeSubject.next(newMode);
    localStorage.setItem('darkMode', JSON.stringify(newMode));
    this.applyDarkMode(newMode);
    
    // 📢 Notifier les autres tabs/fenêtres instantanément
    this.channel.postMessage(newMode);
  }

  private getInitialMode(): boolean {
    const savedDarkMode = localStorage.getItem('darkMode');
    const prefersDark = window.matchMedia('(prefers-color-scheme: dark)').matches;
    return savedDarkMode ? JSON.parse(savedDarkMode) : prefersDark;
  }

  private applyDarkMode(isDark: boolean): void {
    if (isDark) {
      document.body.classList.add('p-dark');
    } else {
      document.body.classList.remove('p-dark');
    }
  }

  getCurrentMode(): boolean {
    return this.isDarkModeSubject.value;
  }

  ngOnDestroy(): void {
    this.channel.close();
  }
}

// =========================================
// 2️⃣ AUTH SERVICE (OAUTH2-OIDC)
// =========================================

import { Injectable } from '@angular/core';
import { OAuthService } from 'angular-oauth2-oidc';
import { BehaviorSubject, Observable } from 'rxjs';

@Injectable({
  providedIn: 'root'
})
export class AuthInitService {
  private isAuthReadySubject = new BehaviorSubject<boolean>(false);
  isAuthReady$: Observable<boolean> = this.isAuthReadySubject.asObservable();

  constructor(private oauthService: OAuthService) {}

  // 🔑 Appelé par APP_INITIALIZER AVANT le bootstrap
  async initializeAuth(): Promise<void> {
    try {
      // Charger la configuration OIDC
      await this.oauthService.loadDiscoveryDocumentAndTryLogin();
      
      // Charger le profil utilisateur si connecté
      if (this.oauthService.hasValidAccessToken()) {
        await this.oauthService.loadUserProfile();
      }
      
      this.isAuthReadySubject.next(true);
    } catch (error) {
      console.error('Auth initialization failed:', error);
      this.isAuthReadySubject.next(true); // Même en erreur, on considère auth comme "ready"
    }
  }

  getAccessToken(): string {
    return this.oauthService.getAccessToken() || '';
  }

  getUserId(): string {
    return this.oauthService.getIdentityClaims()?.sub || '';
  }

  isLoggedIn(): boolean {
    return this.oauthService.hasValidAccessToken();
  }
}

// =========================================
// 3️⃣ HTTP INTERCEPTOR (SIMPLE & FIABLE)
// =========================================

import { Injectable } from '@angular/core';
import {
  HttpInterceptor,
  HttpRequest,
  HttpHandler,
  HttpEvent,
} from '@angular/common/http';
import { Observable } from 'rxjs';
import { AuthInitService } from '../services/auth-init.service';

@Injectable()
export class AuthInterceptor implements HttpInterceptor {
  constructor(private authService: AuthInitService) {}

  intercept(
    req: HttpRequest<any>,
    next: HttpHandler
  ): Observable<HttpEvent<any>> {
    const token = this.authService.getAccessToken();
    const userId = this.authService.getUserId();

    // Ajouter les headers si les valeurs existent
    if (token || userId) {
      req = req.clone({
        setHeaders: {
          ...(token && { Authorization: `Bearer ${token}` }),
          ...(userId && { 'X-User-Id': userId }),
        },
      });
    }

    return next.handle(req);
  }
}

// =========================================
// 4️⃣ APP.MODULE.TS (CONFIGURATION FINALE)
// =========================================

import { NgModule, APP_INITIALIZER } from '@angular/core';
import { BrowserModule } from '@angular/platform-browser';
import { HttpClientModule, HTTP_INTERCEPTORS } from '@angular/common/http';
import { OAuthModule } from 'angular-oauth2-oidc';

import { AppComponent } from './app.component';
import { DarkModeService } from './services/navbar/dark-mode.service';
import { AuthInitService } from './services/auth-init.service';
import { AuthInterceptor } from './interceptors/auth.interceptor';

// Factory functions pour APP_INITIALIZER
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
    // 🔴 ORDRE CRITIQUE : DarkMode AVANT Auth
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
    // Interceptor HTTP
    {
      provide: HTTP_INTERCEPTORS,
      useClass: AuthInterceptor,
      multi: true,
    },
  ],
  bootstrap: [AppComponent],
})
export class AppModule {}

// =========================================
// 5️⃣ NAVBARS SIMPLIFIÉS (PLUS DE SUBSCRIBE EN BOUCLE)
// =========================================

// default-navbar.component.ts
import { Component, OnInit, OnDestroy } from '@angular/core';
import { DarkModeService } from '../../services/navbar/dark-mode.service';
import { SharedService } from '../../services/shared.service';
import { Subject } from 'rxjs';
import { takeUntil } from 'rxjs/operators';

@Component({
  selector: 'app-default-navbar',
  templateUrl: './default-navbar.component.html',
  styleUrls: ['./default-navbar.component.scss']
})
export class DefaultNavbarComponent implements OnInit, OnDestroy {
  isDarkMode$ = this.darkModeService.isDarkMode$;
  userInfo$ = this.sharedService.userInfo$;
  private destroy$ = new Subject<void>();

  constructor(
    private darkModeService: DarkModeService,
    private sharedService: SharedService
  ) {}

  ngOnInit(): void {
    // Plus besoin de subscribe manuellement → utiliser async pipe en template
  }

  toggleDarkMode(): void {
    this.darkModeService.toggleDarkMode();
  }

  ngOnDestroy(): void {
    this.destroy$.next();
    this.destroy$.complete();
  }
}

// default-navbar.component.html
<button (click)="toggleDarkMode()">
  {{ (isDarkMode$ | async) ? '☀️' : '🌙' }}
</button>
<div *ngIf="userInfo$ | async as user">
  <span>{{ user.username }}</span>
</div>