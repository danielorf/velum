require "rails_helper"

# rubocop:disable RSpec/ExampleLength
describe "Feature: External Cerificate settings", js: true do

  let!(:user) { create(:user) }
  let!(:fixture_path) { RSpec.configuration.fixture_path }

  let(:ssl_cert_file_a) { File.join(fixture_path, "ext_cert_ssl_a.pem") }
  let(:ssl_key_file_a) { File.join(fixture_path, "ext_cert_key_a.pem") }
  let(:ssl_cert_file_b) { File.join(fixture_path, "ext_cert_ssl_b.pem") }
  let(:ssl_key_file_b) { File.join(fixture_path, "ext_cert_key_b.pem") }
  let(:ssl_cert_file_malformed) { File.join(fixture_path, "ext_cert_ssl_mal.pem") }
  let(:ssl_key_file_malformed) { File.join(fixture_path, "ext_cert_key_mal.pem") }
  let(:expired_cert) { File.join(fixture_path, "expired_cert.pem") }
  let(:key_for_expired_cert) { File.join(fixture_path, "key_for_expired_cert.pem") }

  before do
    setup_done
    login_as user, scope: :user
  end

  describe "#index" do
    before do
      visit settings_ext_cert_index_path
    end

    # Success Conditions

    it "barely does the bare minimum" do
      expect(page).to have_http_status(:success)
      expect(page).to have_content("External Certificates")
    end

    it "saves the form with nothing attached" do
      click_button("Save")
      expect(page).to have_http_status(:success)
      expect(page).to have_content("External Certificate settings successfully saved.")
      expect(page).to have_css(".alert-message")
    end

    it "sucessfully uploads velum cert/key" do
      attach_file("external_certificate_velum_cert", ssl_cert_file_a)
      attach_file("external_certificate_velum_key", ssl_key_file_a)

      click_button("Save")
      expect(page).to have_http_status(:success)
      expect(page).to have_content("External Certificate settings successfully saved.")
    end

    it "sucessfully uploads kubeAPI cert/key" do
      attach_file("external_certificate_kubeapi_cert", ssl_cert_file_a)
      attach_file("external_certificate_kubeapi_key", ssl_key_file_a)

      click_button("Save")
      expect(page).to have_http_status(:success)
      expect(page).to have_content("External Certificate settings successfully saved.")
    end

    it "sucessfully uploads dex cert/key" do
      attach_file("external_certificate_dex_cert", ssl_cert_file_a)
      attach_file("external_certificate_dex_key", ssl_key_file_a)

      click_button("Save")
      expect(page).to have_http_status(:success)
      expect(page).to have_content("External Certificate settings successfully saved.")
    end

    it "sucessfully uploads velum, kubeAPI, and dex cert/key" do
      attach_file("external_certificate_velum_cert", ssl_cert_file_a)
      attach_file("external_certificate_velum_key", ssl_key_file_a)
      attach_file("external_certificate_kubeapi_cert", ssl_cert_file_a)
      attach_file("external_certificate_kubeapi_key", ssl_key_file_a)
      attach_file("external_certificate_dex_cert", ssl_cert_file_a)
      attach_file("external_certificate_dex_key", ssl_key_file_a)

      click_button("Save")
      expect(page).to have_http_status(:success)
      expect(page).to have_content("External Certificate settings successfully saved.")
    end

    it "sucessfully lists Subject Alternative Names" do
      attach_file("external_certificate_velum_cert", ssl_cert_file_b)
      attach_file("external_certificate_velum_key", ssl_key_file_b)

      click_button("Save")
      expect(page).to have_http_status(:success)
      expect(page).to have_content("ftp.example.com")
    end

    # Faiure Conditions

    it "uploads malformed velum certificate" do
      attach_file("external_certificate_velum_cert", ssl_cert_file_malformed)
      attach_file("external_certificate_velum_key", ssl_key_file_a)

      click_button("Save")
      expect(page).to have_http_status(:unprocessable_entity)
      expect(page).to have_content("Invalid Velum certificate, check format and try again")
    end

    it "uploads malformed velum key" do
      attach_file("external_certificate_velum_cert", ssl_cert_file_a)
      attach_file("external_certificate_velum_key", ssl_key_file_malformed)

      click_button("Save")
      expect(page).to have_http_status(:unprocessable_entity)
      expect(page).to have_content("Invalid Velum key, check format and try again.")
    end

    it "uploads malformed kubeAPI certificate" do
      attach_file("external_certificate_kubeapi_cert", ssl_cert_file_malformed)
      attach_file("external_certificate_kubeapi_key", ssl_key_file_a)

      click_button("Save")
      expect(page).to have_http_status(:unprocessable_entity)
      expect(page).to have_content("Invalid Kubernetes API certificate, check format " \
        "and try again")
    end

    it "uploads malformed kubeAPI key" do
      attach_file("external_certificate_kubeapi_cert", ssl_cert_file_a)
      attach_file("external_certificate_kubeapi_key", ssl_key_file_malformed)

      click_button("Save")
      expect(page).to have_http_status(:unprocessable_entity)
      expect(page).to have_content("Invalid Kubernetes API key, check format and try " \
        "again.")
    end

    it "uploads malformed dex certificate" do
      attach_file("external_certificate_dex_cert", ssl_cert_file_malformed)
      attach_file("external_certificate_dex_key", ssl_key_file_a)

      click_button("Save")
      expect(page).to have_http_status(:unprocessable_entity)
      expect(page).to have_content("Invalid Dex certificate, check format and try again")
    end

    it "uploads malformed dex key" do
      attach_file("external_certificate_dex_cert", ssl_cert_file_a)
      attach_file("external_certificate_dex_key", ssl_key_file_malformed)

      click_button("Save")
      expect(page).to have_http_status(:unprocessable_entity)
      expect(page).to have_content("Invalid Dex key, check format and try again.")
    end

    it "uploads only velum certificate" do
      attach_file("external_certificate_velum_cert", ssl_cert_file_a)

      click_button("Save")
      expect(page).to have_http_status(:unprocessable_entity)
      expect(page).to have_content("Error with Velum, certificate and key must be uploaded " \
        "together.")
    end

    it "uploads only velum key" do
      attach_file("external_certificate_velum_key", ssl_key_file_a)

      click_button("Save")
      expect(page).to have_http_status(:unprocessable_entity)
      expect(page).to have_content("Error with Velum, certificate and key must be uploaded " \
        "together.")
    end

    it "uploads only velum, kubeAPI, and dex certificates" do
      attach_file("external_certificate_velum_cert", ssl_cert_file_a)
      attach_file("external_certificate_kubeapi_cert", ssl_cert_file_a)
      attach_file("external_certificate_dex_cert", ssl_cert_file_a)

      click_button("Save")
      expect(page).to have_http_status(:unprocessable_entity)
      expect(page).to have_content("Error with Velum, certificate and key must be uploaded " \
        "together.")
    end

    it "uploads only velum, kubeAPI, and dex keys" do
      attach_file("external_certificate_velum_key", ssl_key_file_a)
      attach_file("external_certificate_kubeapi_key", ssl_key_file_a)
      attach_file("external_certificate_dex_key", ssl_key_file_a)

      click_button("Save")
      expect(page).to have_http_status(:unprocessable_entity)
      expect(page).to have_content("Error with Velum, certificate and key must be uploaded " \
        "together.")
    end

    it "uploads mismatched velum cert/key 1" do
      attach_file("external_certificate_velum_cert", ssl_cert_file_a)
      attach_file("external_certificate_velum_key", ssl_key_file_b)

      click_button("Save")
      expect(page).to have_http_status(:unprocessable_entity)
      expect(page).to have_content("Certificate/Key pair invalid.  Ensure Certificate and Key " \
        "are matching.")
    end

    it "uploads mismatched velum cert/key 2" do
      attach_file("external_certificate_velum_cert", ssl_cert_file_b)
      attach_file("external_certificate_velum_key", ssl_key_file_a)

      click_button("Save")
      expect(page).to have_http_status(:unprocessable_entity)
      expect(page).to have_content("Certificate/Key pair invalid.  Ensure Certificate and Key " \
        "are matching.")
    end

    it "uploads mismatched velum, kubeAPI, and dex cert/key" do
      attach_file("external_certificate_velum_cert", ssl_cert_file_a)
      attach_file("external_certificate_velum_key", ssl_key_file_b)
      attach_file("external_certificate_kubeapi_cert", ssl_cert_file_a)
      attach_file("external_certificate_kubeapi_key", ssl_key_file_b)
      attach_file("external_certificate_dex_cert", ssl_cert_file_a)
      attach_file("external_certificate_dex_key", ssl_key_file_b)

      click_button("Save")
      expect(page).to have_http_status(:unprocessable_entity)
      expect(page).to have_content("Certificate/Key pair invalid.  Ensure Certificate and Key " \
        "are matching.")
    end

    it "uploads velum cert with invalid date range" do
      attach_file("external_certificate_velum_cert", expired_cert)
      attach_file("external_certificate_velum_key", key_for_expired_cert)

      click_button("Save")
      expect(page).to have_http_status(:unprocessable_entity)
      expect(page).to have_content("Certificate out of valid date range")
    end
  end
end
# rubocop:enable RSpec/ExampleLength
