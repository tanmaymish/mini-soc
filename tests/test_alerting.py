import pytest
from unittest.mock import patch, MagicMock
from app.alerting.dispatcher import AlertDispatcher
from app.alerting.webhook import WebhookAlerter


class TestAlertDispatcher:

    def test_dispatcher_respects_severity_threshold(self):
        """Dispatcher should drop alerts below the configured threshold."""
        config = {
            "WEBHOOK_URL": "http://dummy.url",
            "ALERT_MIN_SEVERITY": "high"
        }
        dispatcher = AlertDispatcher(config)

        # Mock the destination's send_alert method
        mock_alerter = MagicMock()
        dispatcher.destinations = [mock_alerter]

        # 1. Low severity alert -> should be dropped
        low_alert = {"rule_name": "test", "severity": "low"}
        dispatcher.dispatch(low_alert)
        mock_alerter.send_alert.assert_not_called()

        # 2. Medium severity alert -> should be dropped
        med_alert = {"rule_name": "test", "severity": "medium"}
        dispatcher.dispatch(med_alert)
        mock_alerter.send_alert.assert_not_called()

        # 3. High severity alert -> should be sent
        high_alert = {"rule_name": "test", "severity": "high"}
        dispatcher.dispatch(high_alert)
        mock_alerter.send_alert.assert_called_once_with(high_alert)

        mock_alerter.reset_mock()

        # 4. Critical severity alert -> should be sent
        crit_alert = {"rule_name": "test", "severity": "critical"}
        dispatcher.dispatch(crit_alert)
        mock_alerter.send_alert.assert_called_once_with(crit_alert)

    def test_dispatcher_no_webhook_configured(self):
        """If no webhook URL is in config, dispatcher should have no destinations."""
        config = {
            "ALERT_MIN_SEVERITY": "low"
        }
        dispatcher = AlertDispatcher(config)
        
        assert len(dispatcher.destinations) == 0
        
        # Dispatching shouldn't crash
        dispatcher.dispatch({"rule_name": "test", "severity": "critical"})


class TestWebhookAlerter:

    @patch('app.alerting.webhook.requests.post')
    def test_webhook_sends_payload(self, mock_post):
        """Webhook alerter should construct a payload and POST it."""
        mock_post.return_value.status_code = 200

        alerter = WebhookAlerter("http://dummy.webhook/test")
        alert = {
            "rule_name": "brute_force",
            "severity": "critical",
            "source_ip": "1.2.3.4",
            "description": "Explosion imminent",
            "evidence": [{}, {}]
        }

        success = alerter.send_alert(alert)
        
        assert success is True
        mock_post.assert_called_once()
        
        # Check that the URL and timeout were passed
        args, kwargs = mock_post.call_args
        assert args[0] == "http://dummy.webhook/test"
        assert kwargs["timeout"] == 2.0
        
        # Check that the payload was JSON and contained the severity
        payload = kwargs["json"]
        assert "critical" in payload["attachments"][0]["fields"][0]["value"].lower()

    @patch('app.alerting.webhook.requests.post')
    def test_webhook_handles_failures(self, mock_post):
        """Webhook alerter should gracefully return False on HTTP error."""
        mock_post.return_value.status_code = 500
        alerter = WebhookAlerter("http://dummy.webhook/test")
        
        success = alerter.send_alert({"severity": "high"})
        assert success is False
