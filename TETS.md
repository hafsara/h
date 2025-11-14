// =========================================
// 1️⃣ APPLICATION CONTEXT SERVICE (LOGOUT UPDATED)
// =========================================

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

// =========================================
// 2️⃣ MENU SERVICE (LOGOUT PARTAGÉ)
// =========================================

import { Injectable } from '@angular/core';
import { Router } from '@angular/router';
import { TokenService } from '../token.service';
import { ApplicationContextService } from './application-context.service';

export interface MenuConfig {
  isDarkMode: boolean;
  toggleDarkMode: () => void;
  navigateToAdmin: () => void;
}

@Injectable({ providedIn: 'root' })
export class MenuService {
  private channel: BroadcastChannel;

  constructor(
    private tokenService: TokenService,
    private appContext: ApplicationContextService,
    private router: Router
  ) {
    this.setupLogoutBroadcasting();
  }

  // 🔑 Setup BroadcastChannel pour écouter les logouts d'autres fenêtres
  private setupLogoutBroadcasting(): void {
    try {
      this.channel = new BroadcastChannel('auth-logout');
      this.channel.onmessage = (event) => {
        if (event.data.type === 'logout-triggered') {
          console.log('Logout detected from another window');
          // Une autre fenêtre a fait un logout
          this.handleLogout();
        }
      };
    } catch (e) {
      console.warn('BroadcastChannel not supported:', e);
    }
  }

  getMainMenu(config: MenuConfig): any[] {
    return [
      {
        label: 'Settings',
        icon: 'pi pi-cog',
        command: () => config.navigateToAdmin()
      },
      {
        label: config.isDarkMode ? 'Light Mode' : 'Dark Mode',
        icon: config.isDarkMode ? 'pi pi-sun' : 'pi pi-moon',
        command: () => config.toggleDarkMode()
      },
      {
        label: 'Logout',
        icon: 'pi pi-power-off',
        command: () => this.logout()
      }
    ];
  }

  // 🔑 Logout - appelle l'API et notifie les autres fenêtres
  logout(): void {
    this.appContext.logout().subscribe({
      next: () => {
        console.log('Logout successful');
        this.broadcastLogout();
        this.handleLogout();
      },
      error: (err) => {
        console.error('Logout failed:', err);
        // Même en erreur, faire le logout local
        this.broadcastLogout();
        this.handleLogout();
      }
    });
  }

  // 📢 Envoyer un message logout aux autres fenêtres
  private broadcastLogout(): void {
    try {
      this.channel.postMessage({
        type: 'logout-triggered',
      });
      console.log('Logout broadcasted to other windows');
    } catch (e) {
      console.warn('Failed to broadcast logout:', e);
    }
  }

  // 🧹 Nettoyer les données locales et rediriger
  private handleLogout(): void {
    this.tokenService.logout();
    this.router.navigate(['/access-control']);
  }

  ngOnDestroy(): void {
    if (this.channel) {
      this.channel.close();
    }
  }
}

// =========================================
// 3️⃣ NAVBAR COMPONENT (LOGOUT UPDATED)
// =========================================

import { Component, Output, EventEmitter, OnInit, OnDestroy, Input } from '@angular/core';
import { fromEvent, Subscription } from 'rxjs';
import { debounceTime } from 'rxjs/operators';
import { TokenService } from '../../services/token.service';
import { SharedService } from '../../services/shared.service';
import { Router } from '@angular/router';
import { ApplicationMonitorService } from '../../services/navbar/application-monitor.service';
import { MessageService } from 'primeng/api';
import { AppSelectionService } from '../../services/navbar/app-selection.service';
import { MenuService, MenuConfig } from '../../services/navbar/menu.service';
import { SidebarStateService } from '../../services/navbar/sidebar-state.service';
import { DarkModeService } from '../../services/navbar/dark-mode.service';
import { ApplicationContextService } from '../../services/application-context.service';
import { Subject, takeUntil } from 'rxjs';

@Component({
  selector: 'app-navbar',
  templateUrl: './navbar.component.html',
  styleUrls: ['./navbar.component.scss']
})
export class NavbarComponent implements OnInit, OnDestroy {
  @Output() appOptionsLoaded = new EventEmitter<{ name: string; token: string }[]>();
  @Output() selectedAppIdsChange = new EventEmitter<string[]>();
  @Output() menuItemSelected = new EventEmitter<string>();
  @Output() createForm = new EventEmitter<void>();
  @Output() adminTabSelected = new EventEmitter<string>();
  @Input() isAdminMode = false;

  isMobile = false;
  isSidebarCollapsed = true;
  isMobileOpen = false;
  showSidebar = true;
  private resizeSubscription: Subscription | null = null;
  isDarkMode = false;
  userInfo = {
    uid: '',
    username: '',
    avatar: '',
  };

  appOptions: { name: string; token: string }[] = [];
  selectedApps: string[] = [];
  menuItems: any[] = [];

  private destroy$ = new Subject<void>();
  private updateChannel!: BroadcastChannel;
  private logoutChannel!: BroadcastChannel;

  constructor(
    private tokenService: TokenService,
    private sharedService: SharedService,
    private router: Router,
    private appMonitor: ApplicationMonitorService,
    private messageService: MessageService,
    public appSelection: AppSelectionService,
    private menuService: MenuService,
    private sidebarState: SidebarStateService,
    private darkModeService: DarkModeService,
    private appContext: ApplicationContextService
  ) {}

  ngOnInit() {
    this.initializeDarkMode();
    this.initializeUserInfo();
    this.initializeAppSelection();
    this.initializeMenu();
    this.setupTabSync();
    this.setupLogoutSync();
    this.setupAppMonitoring();

    this.checkScreenSize();
    this.resizeSubscription = fromEvent(window, 'resize')
      .pipe(debounceTime(300))
      .subscribe(() => this.checkScreenSize());
    this.sidebarState.setCollapsed(this.isSidebarCollapsed);

    this.darkModeService.isDarkMode$.pipe(
      takeUntil(this.destroy$)
    ).subscribe(isDark => {
      this.isDarkMode = isDark;
      this.initializeMenu();
    });
  }

  checkScreenSize() {
    this.isMobile = window.innerWidth <= 992;
    this.isMobileOpen = false;
  }

  private initializeUserInfo(): void {
    this.sharedService.userInfo$
      .pipe(takeUntil(this.destroy$))
      .subscribe(data => {
        this.userInfo = {
          uid: data.uid || '',
          username: data.username || 'User',
          avatar: data.avatar || '',
        };
      });
  }

  private initializeAppSelection(): void {
    const savedSelection = localStorage.getItem(this.appSelection.localStorageKey);
    this.updateAppOptions();
    this.appSelection.initializeWithAppOptions();

    this.appSelection.initializeSelection(savedSelection);

    this.appSelection.selection$
      .pipe(takeUntil(this.destroy$))
      .subscribe(selection => {
        this.selectedApps = selection;
        this.emitSelectedAppIds();
      });

    this.tokenService.tokenUpdates
      .pipe(takeUntil(this.destroy$))
      .subscribe(() => {
        this.updateAppOptions();
      });
  }

  private emitSelectedAppIds(): void {
    this.selectedAppIdsChange.emit(this.appSelection.getDecodedAppIds());
  }

  onAppSelectionChange(event: any): void {
    this.appSelection.updateSelection(event.value);
  }

  hasAvailableApps(): boolean {
    return this.appSelection.currentAppOptions.length > 0;
  }

  private updateAppOptions(): void {
    const appData = this.tokenService.getAppNames();
    this.appOptions = appData.map(app => ({
      name: app.name || 'Unknown',
      token: app.token || ''
    }));
    this.appOptionsLoaded.emit(this.appOptions);
  }

  private setupTabSync(): void {
    this.updateChannel = new BroadcastChannel('app-updates');
    this.updateChannel.onmessage = (event) => {
      if (event.data.type === 'self-update') {
        this.tokenService.markSelfUpdate(event.data.appId);
        setTimeout(() => window.location.reload(), 1000);
      }
    };
  }

  // 🔑 Écouter les logouts des autres fenêtres
  private setupLogoutSync(): void {
    try {
      this.logoutChannel = new BroadcastChannel('auth-logout');
      this.logoutChannel.onmessage = (event) => {
        if (event.data.type === 'logout-triggered') {
          console.log('Logout detected from another window in navbar');
          // Une autre fenêtre a fait logout, faire le même localement
          this.handleRemoteLogout();
        }
      };
    } catch (e) {
      console.warn('BroadcastChannel for logout not supported:', e);
    }
  }

  // 🧹 Nettoyer à la détection d'un logout distant
  private handleRemoteLogout(): void {
    this.tokenService.logout();
    this.router.navigate(['/access-control']);
  }

  private setupAppMonitoring(): void {
    this.appSelection.getDecodedAppIds().forEach(appId => {
      this.appMonitor.listenForAppChange(appId)
        .pipe(takeUntil(this.destroy$))
        .subscribe(() => this.handleAppChange(appId));
    });
  }

  private handleAppChange(appId: string): void {
    if (this.tokenService.shouldIgnoreUpdate(appId)) return;

    this.messageService.add({
      severity: 'error',
      summary: 'App Changed',
      detail: 'This application was updated. You have been disconnected to ensure consistency.',
      key: 'app-change-toast',
      life: 6000
    });

    setTimeout(() => this.logout(), 5000);
  }

  ngOnDestroy(): void {
    if (this.resizeSubscription) {
      this.resizeSubscription.unsubscribe();
    }
    if (this.logoutChannel) {
      this.logoutChannel.close();
    }
    this.destroy$.next();
    this.destroy$.complete();
  }

  // ✅ Logout appelé localement
  logout(): void {
    this.appContext.logout().subscribe({
      next: () => {
        console.log('Logout successful from navbar');
        // Notifier les autres fenêtres
        try {
          this.logoutChannel.postMessage({
            type: 'logout-triggered',
          });
        } catch (e) {
          console.warn('Failed to broadcast logout from navbar:', e);
        }
        this.tokenService.logout();
        this.router.navigate(['/access-control']);
      },
      error: (err) => {
        console.error('Logout failed:', err);
        this.tokenService.logout();
        this.router.navigate(['/access-control']);
      }
    });
  }

  navigateToAdminPanel(): void {
    this.router.navigate(['/admin/settings']);
  }

  onToggleSidebar() {
    if (this.isMobile) {
      this.isMobileOpen = !this.isMobileOpen;
      this.sidebarState.setMobileOpen(this.isMobileOpen);
      this.isSidebarCollapsed = false;
    } else {
      this.isSidebarCollapsed = !this.isSidebarCollapsed;
      this.sidebarState.setCollapsed(this.isSidebarCollapsed);
    }
  }

  onCreateForm() {
    this.createForm.emit();
  }

  onMenuItemSelected(status: string) {
    this.menuItemSelected.emit(status);
  }

  onAdminTabSelected(tabId: string) {
    this.adminTabSelected.emit(tabId);
  }

  toggleDarkMode(): void {
    this.darkModeService.toggleDarkMode();
  }

  private initializeMenu(): void {
    const menuConfig: MenuConfig = {
      isDarkMode: this.isDarkMode,
      toggleDarkMode: () => this.toggleDarkMode(),
      navigateToAdmin: () => this.navigateToAdminPanel()
    };

    this.menuItems = this.menuService.getMainMenu(menuConfig);
  }

  private initializeDarkMode(): void {
    this.isDarkMode = this.darkModeService.getCurrentMode();
  }
}