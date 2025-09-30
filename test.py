# workflow/tasks/operations/notify.py
import logging
from datetime import datetime, timedelta
from typing import Dict, List

from sqlalchemy import and_, or_

from api.models import Application, FormContainer, WorkflowStep
from workflow.emails.email_manager import MailManager
from workflow.celery_app import celery_app as app
from workflow.tasks.core.base import BaseWorkflowTask, workflow_task

logger = logging.getLogger(__name__)


@app.task(base=BaseWorkflowTask, bind=True)
@workflow_task(max_retries=3, retry_delay=300)
def notify_unresolved_forms(self) -> Dict:
    """
    Tâche périodique qui notifie les formulaires non résolus
    - Lit la config en base à chaque exécution
    - Respecte l'intervalle X jours par application
    """

    def task_handler(context: Dict) -> Dict:
        results = {
            'applications_processed': 0,
            'notifications_sent': 0,
            'errors': 0,
            'details': []
        }

        # Charger TOUTES les applications à chaque exécution
        applications = Application.query.filter_by(active=True).all()

        for app_cfg in applications:
            try:
                app_result = process_application_notifications(app_cfg)
                results['applications_processed'] += 1
                results['notifications_sent'] += app_result['notifications_sent']
                results['errors'] += app_result['errors']
                results['details'].append(app_result)

            except Exception as e:
                logger.error(f"Error processing application {app_cfg.name}: {str(e)}")
                results['errors'] += 1
                results['details'].append({
                    'application': app_cfg.name,
                    'status': 'error',
                    'error': str(e)
                })

        logger.info(
            f"Cron executed: {results['applications_processed']} apps, "
            f"{results['notifications_sent']} notifications, "
            f"{results['errors']} errors"
        )

        return results

    return self._handle_task(None, {'task_type': 'global_cron'}, task_handler)


def process_application_notifications(app_cfg: Application) -> Dict:
    """
    Traite les notifications pour une application spécifique
    """
    delay_days = getattr(app_cfg, 'notify_after_days', 7) or 7
    #             calendar_service = CalendarService("FR")
#    threshold = calendar_service.calculate_working_days(now, -delay_days)

    threshold_date = datetime.utcnow() - timedelta(days=delay_days)

    logger.info(f"Processing {app_cfg.name} - delay: {delay_days} days")

    # Trouver les formulaires problématiques
    unresolved_forms = find_unresolved_forms(app_cfg.id, threshold_date)

    if not unresolved_forms:
        return {
            'application': app_cfg.name,
            'notifications_sent': 0,
            'errors': 0,
            'status': 'no_forms_found'
        }

    # Envoyer les notifications
    return send_notifications_for_forms(unresolved_forms, app_cfg, delay_days)


def find_unresolved_forms(application_id: str, threshold_date: datetime) -> List[FormContainer]:
    """
    Trouve les formulaires non résolus sans activité récente
    """
    return FormContainer.query.filter(
        FormContainer.application_id == application_id,
        FormContainer.status.in_(["pending", "escalated"]),
        FormContainer.updated_at < threshold_date,

        # Vérifier qu'aucune étape de workflow récente n'existe
        ~FormContainer.workflow_steps.any(
            and_(
                WorkflowStep.step_type.in_(['reminder', 'escalation', 'response']),
                WorkflowStep.updated_at >= threshold_date
            )
        )
    ).all()


def send_notifications_for_forms(
        forms: List[FormContainer],
        app_cfg: Application,
        delay_days: int
) -> Dict:
    """
    Envoie les notifications pour une liste de formulaires
    """
    sent_count = 0
    error_count = 0

    for form_container in forms:
        try:
            # Déterminer le template en fonction du statut
            template_type = determine_notification_template(form_container)

            # Préparer les substitutions
            substitutions = {
                'delay_days': delay_days,
                'days_since_creation': (datetime.utcnow() - form_container.created_at).days,
                'form_id': form_container.id,
                'form_title': form_container.title,
                'last_update': form_container.updated_at.strftime('%Y-%m-%d %H:%M')
            }

            MailManager.send_email(
                form_container=form_container,
                template_type=template_type,
                substitutions=substitutions,
                workflow_step="auto-notify"
            )
            sent_count += 1

        except Exception as e:
            logger.error(
                f"Failed to send notification for form {form_container.id}: {str(e)}"
            )
            error_count += 1

    return {
        'application': app_cfg.name,
        'notifications_sent': sent_count,
        'errors': error_count,
        'forms_processed': len(forms),
        'status': 'completed'
    }


def determine_notification_template(form_container: FormContainer) -> str:
    """
    Détermine le template à utiliser en fonction du statut
    """
    if form_container.status == "escalated":
        return "escalation-reminder"
    elif form_container.status == "pending":
        return "pending-reminder"
    else:
        return "generic-reminder"

        #
        #
        #
        # 'notify-unresolved-forms': {
        #     'task': 'workflow.tasks.operations.notify.notify_unresolved_forms',
        #     'schedule': timedelta(days=1),
        #     'options': {
        #         'queue': 'beat_tasks',
        #         'priority': 5
        #     }
        # }
::ng-deep .p-inputnumber {
  max-width: 120px; /* réduit la largeur */
}

::ng-deep .p-inputnumber .p-inputtext {
  text-align: center; /* centre le chiffre */
  padding: 0.25rem 0.5rem; /* réduit le padding */
  font-size: 14px; /* taille plus fine */
}

::ng-deep .p-inputnumber .p-button {
  height: 32px; /* rend les boutons plus petits */
  width: 32px;
  padding: 0;
  border-radius: 6px; /* arrondit un peu les boutons */
}

::ng-deep .p-inputnumber .p-button.p-button-success {
  background: #00c853; /* vert plus sympa */
  border: none;
}

::ng-deep .p-inputnumber .p-button.p-button-danger {
  background: #d32f2f; /* rouge plus soft */
  border: none;
}
