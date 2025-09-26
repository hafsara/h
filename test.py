<p-toast></p-toast>

<div *ngIf="isLoading; else accessForm" class="spinner-container">
  <p-progressSpinner ariaLabel="loading"></p-progressSpinner>
</div>

<ng-template #accessForm>
  <app-default-navbar *ngIf="!isLoading"></app-default-navbar>

  <div class="page-background">
    <div class="card-wrapper">
      <p-card class="access-card">
        <h2>Enter Applications ID</h2>

        <p-chips
          [ngModel]="tokenValues"
          (onAdd)="onTokenAdd($event)"
          (onRemove)="onTokenRemove($event)"
          (keydown.enter)="$event.preventDefault()"
          placeholder="Enter tokens"
          separator=","
          allowDuplicate="false"
          class="w-100">
        </p-chips>

        <!-- Affichage d’erreurs spécifiques -->
        <div *ngFor="let token of tokens">
          <small *ngIf="token.status === 'invalid'" class="error-msg">
            {{ token.errorMessage }}
          </small>
        </div>

        <div class="flex pt-4 justify-content-end">
          <p-button
            label="Enter"
            icon="pi pi-arrow-right"
            iconPos="right"
            (onClick)="submitTokens()"
            [disabled]="!canSubmit()"
            [loading]="isSubmitting">
          </p-button>
        </div>
      </p-card>
    </div>
  </div>
</ng-template>





.p-chips-token {
  &.valid {
    background-color: #d4edda !important;
    color: #155724 !important;
  }
  &.invalid {
    background-color: #f8d7da !important;
    color: #721c24 !important;
  }
}

.error-msg {
  color: #dc3545;
  font-size: 0.8rem;
  margin-left: 5px;
}
