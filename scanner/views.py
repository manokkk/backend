# scanner/views.py

from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from .utils import check_ssl_config, scan_open_ports, check_http_headers, test_xss, test_sql_injection
import json
import logging
import re

# Set up logging
logger = logging.getLogger(__name__)

# Simple domain validation
def is_valid_domain(domain):
    # Basic regex to check if domain looks valid (e.g., google.com, example.org)
    regex = re.compile(r'^(?:http(s)?://)?([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$')
    return re.match(regex, domain) is not None

def health_check(request):
    return JsonResponse({"status": "ok"}, status=200)

@csrf_exempt
def perform_scan(request):
    if request.method == 'POST':
        try:
            # Parse the request body to get the domain
            data = json.loads(request.body)
            domain = data.get('domain')

            if not domain:
                logger.error("No domain provided")
                return JsonResponse({"error": "Domain is required"}, status=400)

            # Log the domain to be scanned
            logger.info(f"Scanning domain: {domain}")

            # Step 1: Check SSL Configurations
            ssl_config = check_ssl_config(domain)

            # Step 2: Scan open ports using nmap
            open_ports = scan_open_ports(domain)

            # Combine results into a single response
            response_data = {
                "ssl_config": ssl_config,
                "open_ports": open_ports
            }

            return JsonResponse(response_data, status=200)
        
        except json.JSONDecodeError:
            logger.error("Invalid JSON input")
            return JsonResponse({"error": "Invalid JSON"}, status=400)
        
        except Exception as e:
            logger.error(f"Error occurred: {str(e)}")
            return JsonResponse({"error": str(e)}, status=500)

    # If not POST request, return 405 Method Not Allowed
    return JsonResponse({"error": "Only POST method is allowed"}, status=405)

