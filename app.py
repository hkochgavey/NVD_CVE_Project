from flask import Flask, request, jsonify, render_template
import requests
import sqlite3
from datetime import datetime, timedelta
import threading
import time
import json
import ast

app = Flask(__name__)

# Database Initialization
db_file = 'cve_database.db'

def init_db():
    conn = sqlite3.connect(db_file)
    cursor = conn.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS cve_data (
    cve_id TEXT PRIMARY KEY,
    source_identifier TEXT,
    published TEXT,
    last_modified TEXT,
    vuln_status TEXT,
    description TEXT,
    cvss_version TEXT,
    cvss_vector TEXT,
    base_score REAL,
    access_vector TEXT,
    access_complexity TEXT,
    authentication TEXT,
    confidentiality_impact TEXT,
    integrity_impact TEXT,
    availability_impact TEXT,
    exploitability_score REAL,
    impact_score REAL,
    cpe_match TEXT
)''')
    conn.commit()
    conn.close()

init_db()

# Fetch CVE Data from API
def fetch_cve_data(start_index=0, results_per_page=10):
    base_url = 'https://services.nvd.nist.gov/rest/json/cves/2.0'
    params = {
        'startIndex': start_index,
        'resultsPerPage': results_per_page
    }
    response = requests.get(base_url, params=params)
    if response.status_code == 200:
        return response.json()
    return None

# Store CVE data into Database
def store_cve_data(cve_list):
    conn = sqlite3.connect(db_file)
    cursor = conn.cursor()
    for cve in cve_list:
        cvss_metrics = cve.get('metrics', {}).get('cvssMetricV2', [{}])[0].get('cvssData', {})
        cvss_version = cvss_metrics.get('version', 'N/A')
        cvss_vector = cvss_metrics.get('vectorString', 'N/A')
        base_score = cvss_metrics.get('baseScore', 0)
        access_vector = cvss_metrics.get('accessVector', 'N/A')
        access_complexity = cvss_metrics.get('accessComplexity', 'N/A')
        authentication = cvss_metrics.get('authentication', 'N/A')
        confidentiality_impact = cvss_metrics.get('confidentialityImpact', 'N/A')
        integrity_impact = cvss_metrics.get('integrityImpact', 'N/A')
        availability_impact = cvss_metrics.get('availabilityImpact', 'N/A')
        exploitability_score = cve.get('metrics', {}).get('cvssMetricV2', [{}])[0].get('exploitabilityScore', 0)
        impact_score = cve.get('metrics', {}).get('cvssMetricV2', [{}])[0].get('impactScore', 0)

        cpe_match = cve.get('configurations', [{}])[0].get('nodes', [{}])[0].get('cpeMatch', [])
        cpe_match_data = [
            {
                "vulnerable": match.get("vulnerable", False),
                "criteria": match.get("criteria", ""),
                "matchCriteriaId": match.get("matchCriteriaId", "")
            }
            for match in cpe_match
        ]

        cve_data = (
            cve['id'],
            cve['sourceIdentifier'],
            cve['published'],
            cve['lastModified'],
            cve['vulnStatus'],
            cve['descriptions'][0]['value'],
            cvss_version,
            cvss_vector,
            base_score,
            access_vector,
            access_complexity,
            authentication,
            confidentiality_impact,
            integrity_impact,
            availability_impact,
            exploitability_score,
            impact_score,
            str(cpe_match_data)
        )
        cursor.execute('''
            INSERT OR REPLACE INTO cve_data (
                cve_id, source_identifier, published, last_modified, vuln_status, description,
                cvss_version, cvss_vector, base_score, access_vector, access_complexity,
                authentication, confidentiality_impact, integrity_impact, availability_impact,
                exploitability_score, impact_score, cpe_match
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,?)
        ''', cve_data)
    conn.commit()
    conn.close()

# Periodic Synchronization
def sync_cve_data():
    start_index = 0
    results_per_page = 100
    while True:
        data = fetch_cve_data(start_index, results_per_page)
        if data and 'vulnerabilities' in data:
            store_cve_data([v['cve'] for v in data['vulnerabilities']])
            start_index += results_per_page
        else:
            break
        time.sleep(10)  # Sleep between batches

# Start synchronization in a thread
def start_sync():
    threading.Thread(target=sync_cve_data, daemon=True).start()

start_sync()

# Routes for API
@app.route('/cves/list', methods=['GET'])
def list_cves():
    conn = sqlite3.connect(db_file)
    cursor = conn.cursor()

    cve_id = request.args.get('cve_id')
    print(cve_id)
    year = request.args.get('year')
    score = request.args.get('score')
    days = request.args.get('days')

    query = 'SELECT * FROM cve_data WHERE 1=1'
    params = []
    if cve_id:
        query += ' AND cve_id = ?'
        params.append(cve_id)
    if year:
        query += ' AND published LIKE ?'
        params.append(f'{year}%')
    if score:
        query += ' AND base_score >= ?'
        params.append(float(score))
    if days:
        days_ago = (datetime.now() - timedelta(days=int(days))).strftime('%Y-%m-%d')
        query += ' AND last_modified >= ?'
        params.append(days_ago)

    query += ' ORDER BY published DESC'
    cursor.execute(query, params)
    results = cursor.fetchall()
    conn.close()

    return jsonify(results)

# UI Route
from flask import request, render_template
import sqlite3

@app.route('/cves', methods=['GET'])
def cve_ui():
    page = request.args.get('page', 1, type=int)
    records_per_page = request.args.get('records_per_page', 10, type=int)
    if page < 1:
        page = 1
    if records_per_page not in [10, 50, 100]:
        records_per_page = 10
    offset = (page - 1) * records_per_page

    conn = sqlite3.connect(db_file)
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM cve_data ORDER BY published DESC LIMIT ? OFFSET ?', (records_per_page, offset))
    results = cursor.fetchall()
    formatted_results = []
    for result in results:
        published_date = datetime.strptime(result[2], '%Y-%m-%dT%H:%M:%S.%f') if result[2] else None
        last_modified_date = datetime.strptime(result[3], '%Y-%m-%dT%H:%M:%S.%f') if result[3] else None
        
        formatted_result = {
            **dict(zip([column[0] for column in cursor.description], result)),
            'published': published_date.strftime('%d %b %Y') if published_date else None,
            'last_modified': last_modified_date.strftime('%d %b %Y') if last_modified_date else None
        }
        formatted_results.append(formatted_result)
    print(formatted_results)
    cursor.execute('SELECT COUNT(*) FROM cve_data')
    total = cursor.fetchone()[0]

    conn.close()
    total_pages = (total // records_per_page) + (1 if total % records_per_page > 0 else 0)
    if page > total_pages:
        page = total_pages
    start_page = max(1, page - 2)
    end_page = min(total_pages, start_page + 4)
    return render_template('cves.html', results=formatted_results, total=total, page=page, total_pages=total_pages, records_per_page=records_per_page, start_page=start_page, end_page=end_page)


@app.route('/cves/<cve_id>', methods=['GET'])
def cve_detail(cve_id):
    conn = sqlite3.connect(db_file)
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM cve_data WHERE cve_id = ?', (cve_id,))
    result = cursor.fetchone()
    conn.close()
    print(result)
    if result:
        cpe=ast.literal_eval(result[17])
        print(cpe)
        return render_template('cve_detail.html', cve=result,cpe=cpe)
    return jsonify({'error': 'CVE not found'}), 404

if __name__ == '__main__':
    app.run(debug=True)
