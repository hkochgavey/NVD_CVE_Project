# CVE Data Application

This project is a Flask-based application designed to fetch, store, and display Common Vulnerabilities and Exposures (CVE) data from the National Vulnerability Database (NVD) API. It provides both a RESTful API and a web interface for users to query and view CVE details, with periodic synchronization to keep the data updated.

## Features

- **Periodic Synchronization**: Fetches and stores CVE data at regular intervals from the NVD API.
- **CVE Listing API**: Allows filtering of CVE data by ID, year, CVSS score, and modification date.
- **Detailed CVE View**: Displays detailed information about a CVE, including vulnerability description, CVSS scores, and associated CPE matches.
- **Pagination for CVE Listings**: The UI supports pagination to display a manageable number of CVEs at a time.
- **Database Storage**: CVE data is stored in an SQLite database for fast querying and retrieval.

## Tech Stack

- **Backend**: Flask (Python)
- **Database**: SQLite
- **API**: NVD API for fetching CVE data
- **Frontend**: HTML, CSS, Jinja2 templates for rendering views
- **Threading**: Python’s `threading` module for periodic synchronization

## Requirements

To run this application locally, make sure you have the following:

- Python 3.x
- Flask
- Requests
- SQLite3
- threading (built-in Python module)
- Jinja2 (Flask comes bundled with this)

You can install required Python packages using `pip`:

```bash
pip install flask requests
```

## Setup Instructions

1. **Clone the Repository**

   ```bash
   git clone https://github.com/your-username/cve-data-app.git
   cd cve-data-app
   ```

2. **Set Up Database**

   The `init_db` function initializes the SQLite database and creates the necessary table (`cve_data`). This function runs automatically when the application starts, but you can manually trigger it as well by running:

   ```python
   python
   from app import init_db
   init_db()
   ```

3. **Run the Flask Application**

   Run the Flask app locally:

   ```bash
   python app.py
   ```

   By default, the application will run on `http://127.0.0.1:5000`.

4. **Access the Web Interface**

   Open a browser and navigate to `http://127.0.0.1:5000/cves` to view the CVE listings with pagination.

5. **API Access**

   You can access the API for fetching CVE data using `GET` requests:
   
   - **List CVEs**: `/cves/list?cve_id=<ID>&year=<Year>&score=<Score>&days=<Days>`
   - **Get Specific CVE Details**: `/cves/<cve_id>`

## How the Application Works

### 1. Fetching Data

- The application makes requests to the NVD API to fetch CVE data. The `fetch_cve_data` function is responsible for making requests to the API.
- The API returns CVE information in JSON format, which is processed by the `store_cve_data` function to extract relevant details (e.g., CVSS score, description, CPE matches).

### 2. Storing Data

- The CVE data is stored in an SQLite database. The `cve_data` table is created with the following fields:
  - `cve_id`: Unique identifier for the CVE
  - `source_identifier`: Source identifier of the CVE
  - `published`: Date of publication
  - `last_modified`: Date the CVE was last modified
  - `vuln_status`: Vulnerability status
  - `description`: Vulnerability description
  - `cvss_version`: CVSS version
  - `cvss_vector`: CVSS vector string
  - `base_score`: CVSS base score
  - `access_vector`, `access_complexity`, `authentication`, `confidentiality_impact`, `integrity_impact`, `availability_impact`: CVSS metrics
  - `exploitability_score`: Exploitability score
  - `impact_score`: Impact score
  - `cpe_match`: A list of CPE match data (serialized)

### 3. Periodic Data Synchronization

- The application periodically synchronizes data from the NVD API, ensuring that the database stays up-to-date with the latest CVE information. The synchronization is handled by a background thread that calls the `sync_cve_data` function every 10 seconds, fetching new data in batches.

### 4. API Endpoints

#### `GET /cves/list`

- This endpoint retrieves a list of CVEs, with optional filtering based on:
  - `cve_id`: Filter by CVE ID.
  - `year`: Filter by publication year.
  - `score`: Filter by minimum CVSS base score.
  - `days`: Filter by the last modified date within the last X days.

  Example request:
  
  ```bash
  GET /cves/list?score=7.5&days=30
  ```

#### `GET /cves/<cve_id>`

- This endpoint retrieves detailed information for a specific CVE by its ID.
  
  Example request:
  
  ```bash
  GET /cves/CVE-2021-34527
  ```

### 5. Web Interface

- The web UI displays a paginated list of CVEs.
- Users can view CVE details and see information such as the published date, CVSS score, and a description.
- The UI is implemented using Jinja2 templates, and Flask handles rendering the views.
