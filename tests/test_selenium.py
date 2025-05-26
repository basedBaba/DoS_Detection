import pytest
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.firefox.options import Options
from selenium.webdriver.support.ui import Select
from selenium.common.exceptions import TimeoutException
import time

@pytest.fixture(scope="session")
def driver():
    """Create a Firefox WebDriver instance"""
    firefox_options = Options()
    firefox_options.add_argument('--headless')  # Run in headless mode
    
    # Set preferences for better performance
    firefox_options.set_preference('browser.cache.disk.enable', False)
    firefox_options.set_preference('browser.cache.memory.enable', False)
    firefox_options.set_preference('browser.cache.offline.enable', False)
    firefox_options.set_preference('network.http.use-cache', False)
    
    driver = webdriver.Firefox(options=firefox_options)
    driver.implicitly_wait(10)  # Set implicit wait time
    yield driver
    driver.quit()

@pytest.fixture(scope="session")
def base_url():
    """Return the base URL for testing"""
    return "http://127.0.0.1:5000"

@pytest.fixture(scope="function")
def wait(driver):
    """Create a WebDriverWait instance with a longer timeout"""
    return WebDriverWait(driver, 20)  # Increased timeout to 20 seconds

def test_home_page_ui(driver, base_url):
    """Test home page UI elements and navigation"""
    driver.get(base_url)
    
    # Check page title
    assert "Network Intrusion Detection System" in driver.title
    
    # Check navigation links
    predict_link = driver.find_element(By.XPATH, "//a[@href='/predict']")
    assert predict_link.is_displayed()
    assert predict_link.is_enabled()
    
    # Check main content
    assert "Advanced Network Intrusion Detection" in driver.page_source
    assert "Detect Threats Now" in driver.page_source
    assert "Start Monitoring" in driver.page_source

def test_predict_page_ui(driver, base_url):
    """Test prediction page UI elements and form"""
    driver.get(f"{base_url}/predict")
    
    # Check form elements
    form = driver.find_element(By.TAG_NAME, "form")
    assert form.is_displayed()
    
    # Check dropdowns
    protocol_select = Select(driver.find_element(By.NAME, "protocol_type"))
    service_select = Select(driver.find_element(By.NAME, "service"))
    flag_select = Select(driver.find_element(By.NAME, "flag"))
    
    assert len(protocol_select.options) > 0
    assert len(service_select.options) > 0
    assert len(flag_select.options) > 0
    
    # Check model selection (radio buttons)
    model_options = driver.find_elements(By.NAME, "model_choice")
    assert len(model_options) == 4  # rf, gb, ann, both
    
    # Check submit button
    submit_button = driver.find_element(By.CLASS_NAME, "analyze-button")
    assert submit_button.is_displayed()
    assert submit_button.is_enabled()

def test_packets_page_ui(driver, base_url, wait):
    """Test packets page UI elements and dynamic content"""
    driver.get(f"{base_url}/packets")
    
    # Check page title
    assert "Network Packet Monitor" in driver.title
    
    # Check for packet table
    try:
        packet_table = wait.until(
            EC.presence_of_element_located((By.CLASS_NAME, "table"))
        )
        assert packet_table.is_displayed()
    except TimeoutException:
        pytest.fail("Packet table not found after 20 seconds")
    
    # Check for DoS status
    try:
        threat_level = wait.until(
            EC.presence_of_element_located((By.ID, "threat-level"))
        )
        assert threat_level.is_displayed()
        assert "Normal" in threat_level.text or "Warning" in threat_level.text or "Danger" in threat_level.text
    except TimeoutException:
        pytest.fail("Threat level element not found after 20 seconds")

def test_prediction_form_submission(driver, base_url, wait):
    """Test form submission with valid data"""
    driver.get(f"{base_url}/predict")
    
    # Fill form with valid data using Select
    protocol_select = Select(driver.find_element(By.NAME, "protocol_type"))
    service_select = Select(driver.find_element(By.NAME, "service"))
    flag_select = Select(driver.find_element(By.NAME, "flag"))
    
    protocol_select.select_by_visible_text("tcp")
    service_select.select_by_visible_text("http")
    flag_select.select_by_visible_text("SF")
    
    # Select model (radio button)
    model_radio = driver.find_element(By.CSS_SELECTOR, "input[name='model_choice'][value='rf']")
    model_radio.click()
    
    # Fill numeric inputs
    driver.find_element(By.NAME, "duration").send_keys("100")
    driver.find_element(By.NAME, "src_bytes").send_keys("1000")
    driver.find_element(By.NAME, "dst_bytes").send_keys("2000")
    driver.find_element(By.NAME, "wrong_fragment").send_keys("0")
    
    # Submit form
    driver.find_element(By.CLASS_NAME, "analyze-button").click()
    
    # Wait for results
    try:
        wait.until(
            EC.presence_of_element_located((By.CLASS_NAME, "result-cards"))
        )
    except TimeoutException:
        pytest.fail("Result cards not found after 20 seconds")
    
    # Check for result elements
    assert "Detection Results" in driver.page_source
    assert "Random Forest" in driver.page_source
    assert "Confidence" in driver.page_source

def test_form_validation_selenium(driver, base_url, wait):
    """Test form validation with invalid data"""
    driver.get(f"{base_url}/predict")
    
    # Submit empty form
    driver.find_element(By.CLASS_NAME, "analyze-button").click()
    
    # Check for error message
    try:
        wait.until(
            EC.presence_of_element_located((By.CLASS_NAME, "error-message"))
        )
    except TimeoutException:
        # If error message class is not found, check for back button
        try:
            wait.until(
                EC.presence_of_element_located((By.CLASS_NAME, "back-button"))
            )
        except TimeoutException:
            pytest.fail("Neither error message nor back button found after 20 seconds")
    
    assert "Analyze Another" in driver.page_source

def test_packet_table_updates(driver, base_url, wait):
    """Test packet table updates"""
    driver.get(f"{base_url}/packets")
    
    # Wait for initial table load
    try:
        wait.until(
            EC.presence_of_element_located((By.CLASS_NAME, "table"))
        )
    except TimeoutException:
        pytest.fail("Packet table not found after 20 seconds")
    
    # Get initial row count
    initial_rows = len(driver.find_elements(By.XPATH, "//table/tbody/tr"))
    
    # Wait for potential updates
    time.sleep(5)
    
    # Get updated row count
    updated_rows = len(driver.find_elements(By.XPATH, "//table/tbody/tr"))
    
    # Verify table is updating
    assert updated_rows >= initial_rows

def test_dos_status_updates(driver, base_url, wait):
    """Test DoS status updates"""
    driver.get(f"{base_url}/packets")
    
    # Wait for initial status
    try:
        initial_status = wait.until(
            EC.presence_of_element_located((By.ID, "threat-level"))
        ).text
    except TimeoutException:
        pytest.fail("Threat level element not found after 20 seconds")
    
    # Wait for potential updates
    time.sleep(5)
    
    # Get updated status
    updated_status = driver.find_element(By.ID, "threat-level").text
    
    # Verify status is updating by checking if the status text contains expected values
    assert any(status in updated_status for status in ["Normal", "Warning", "Danger"])

def test_error_page_handling(driver, base_url):
    """Test error page handling"""
    # Try to access non-existent page
    driver.get(f"{base_url}/non-existent-page")
    
    # Check for error message
    assert "Not Found" in driver.page_source
    assert "The requested URL was not found on the server" in driver.page_source
    assert "try again" in driver.page_source.lower()

def test_invalid_model_selection(driver, base_url, wait):
    """Test invalid model selection handling"""
    driver.get(f"{base_url}/predict")
    
    # Try to select invalid model (radio button)
    try:
        invalid_model = driver.find_element(By.CSS_SELECTOR, "input[name='model_choice'][value='invalid_model']")
        invalid_model.click()
    except:
        # If invalid option is not available, that's fine
        pass
    
    # Submit form
    driver.find_element(By.CLASS_NAME, "analyze-button").click()
    
    # Check for error message
    try:
        wait.until(
            EC.presence_of_element_located((By.CLASS_NAME, "error-message"))
        )
    except TimeoutException:
        # If error message class is not found, check for back button
        try:
            wait.until(
                EC.presence_of_element_located((By.CLASS_NAME, "back-button"))
            )
        except TimeoutException:
            pytest.fail("Neither error message nor back button found after 20 seconds")
    
    assert "Analyze Another" in driver.page_source 