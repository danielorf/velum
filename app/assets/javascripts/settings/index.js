$(function() {
  var $mirrorForm = $('.mirror-form');
  var $registryForm = $('.registry-form');
  var $admissionWebhookForm = $('#admission-webhook-form');

  if ($mirrorForm.length) {
    new RegistryForm($mirrorForm);
  }

  if ($registryForm.length) {
    new RegistryForm($registryForm);
  }

  if ($admissionWebhookForm.length) {
    new AdmissionWebhookForm($admissionWebhookForm);
  }
});
