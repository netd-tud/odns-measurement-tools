import os
import time
import sys
from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.chrome.options import Options
from webdriver_manager.chrome import ChromeDriverManager
from selenium.webdriver.support.ui import WebDriverWait
from selenium.common.exceptions import TimeoutException, WebDriverException
from multiprocessing import Lock
from multiprocessing import Pool, cpu_count
import multiprocessing

print("starting")

ip_queue = multiprocessing.Queue()

if len(sys.argv) < 2:
        print("missing input filepath")
        sys.exit(-1)
INPUT_FILE = sys.argv[1]
OUTPUT_DIR = "output_selenium"

# create output directories
os.makedirs(os.path.join(OUTPUT_DIR,"error", "screens"), exist_ok=True)
os.makedirs(os.path.join(OUTPUT_DIR,"ok", "screens"), exist_ok=True)
os.makedirs(os.path.join(OUTPUT_DIR,"error", "html"), exist_ok=True)
os.makedirs(os.path.join(OUTPUT_DIR,"ok", "html"), exist_ok=True)

# read ips from input file
with open(INPUT_FILE, "r") as file:
    for line in file:
        if line.strip():
            ip_queue.put(line.strip())

error_texts = [
    "404 Not Found",
    "404 - Not Found",
    "403 Forbidden",
    "403 - Forbidden", 
    "502 Bad Gateway",
    "502 - Bad Gateway",
    "500 - Internal Server Error",
    "500 Internal Server Error",
    "Site Not Found"
]

def print_w(id, msg):
    print(f"[Worker {id}] {msg}")

def browser_worker(id, queue):
    chrome_options = Options()
    chrome_options.add_argument("--headless")
    #chrome_options.add_argument("--disable-gpu")
    #chrome_options.add_argument("--no-sandbox")
    #chrome_options.add_argument("--disable-dev-shm-usage")
    chrome_options.add_argument("--ignore-certificate-errors") 
    chrome_options.add_argument("--window-size=1400,900")

    # start webdriver
    service = Service(ChromeDriverManager().install())
    driver = webdriver.Chrome(service=service, options=chrome_options)
    # open each ip
    while True:
        ip = queue.get()
        if ip is None: # quit on poison
            driver.quit()
            print_w(id, "Finished processing all IPs.")
            return

        url = f"http://{ip}"
        try:
            print_w(id, f"Processing {url}")

            driver.get("about:blank")
            # try with low timeout
            try:
                driver.set_page_load_timeout(2)
                driver.get(url)
            except TimeoutException:
                print_w(id,f"1st Timeout while loading {url}")
                if driver.page_source.strip() != "<html><head></head><body></body></html>":
                    print_w(id,"got partial page content, retrying")
                    try:
                        # retry with higher timeout
                        driver.set_page_load_timeout(20)
                        driver.get(url)
                    except TimeoutException:
                        print_w(id,f"2nd Timeout while loading {url}, aborting")
                        continue
                else:
                    print_w(id,f"IP {ip} unresponsive")
                    continue

            if driver.page_source.strip() == "<html><head></head><body></body></html>": 
                print_w(id,f"{url} empty page")
                continue

            #print(driver.page_source.strip())

            page_title = driver.title.strip()
            page_source = driver.page_source.lower()

            if any(error.lower() in page_title.lower() or error.lower() in page_source for error in error_texts):
                print_w(id,f"Error page detected ({page_title}). Skipping {url}.")
                screenshot_path = os.path.join(OUTPUT_DIR, "error", "screens", f"{ip}.png")
                html_path = os.path.join(OUTPUT_DIR, "error", "html", f"{ip}.html")
            else: 
                screenshot_path = os.path.join(OUTPUT_DIR, "ok", "screens", f"{ip}.png")
                html_path = os.path.join(OUTPUT_DIR, "ok", "html", f"{ip}.html")

            is_blank = driver.execute_script("""
                    if (!document.body) return true;
                    return document.body.innerText.trim() === "" || 
                        document.body.children.length === 0 ||
                        document.documentElement.innerHTML.replace(/\\s/g, '').length < 50;
                """)
            if is_blank:
                time.sleep(10)

            # save screenshot and html
            driver.save_screenshot(screenshot_path)
            with open(html_path, "w", encoding="utf-8") as html_file:
                html_file.write(driver.page_source)

            print_w(id,f"Saved: {screenshot_path}, {html_path}")
        except WebDriverException as e:
            error_msg = str(e)
            if "ERR_ADDRESS_UNREACHABLE" in error_msg or "ERR_CONNECTION_REFUSED" in error_msg:
                print_w(id,f"{url} {"address unreachable or refused"}")
            print_w(id, f"{url} WebDriverException")
        except Exception as e:
            print_w(id,f"Error processing {url}: {e}")

if __name__ == "__main__":
    num_workers = 24
    print(f"Using {num_workers} parallel processes")

    processes = []

    # use multiple processes =selenium instances so it's faster
    for i in range(num_workers):
        ip_queue.put(None)
        p = multiprocessing.Process(target=browser_worker, args=(i,ip_queue))
        p.start()
        processes.append(p)
        time.sleep(2)

    for p in processes:
        p.join()

    print("done")
