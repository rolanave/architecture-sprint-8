import logging
import os
from flask import Flask, request, send_from_directory
from flask_cors import CORS, cross_origin
import jwt


app = Flask(__name__)
cors = CORS(app)
app.config['CORS_HEADERS'] = 'Content-Type'


DOWNLOAD_FOLDER = '/app/download'
app.config['DOWNLOAD_FOLDER'] = DOWNLOAD_FOLDER


REPORT_FILE_NAME = 'report.txt'
KEYCLOAK_TOKEN_ALG = 'RS256'
KEYCLOAK_PUB_KEY = b'-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA38hwr1D3GTpU40P3JmgmsGhqLkoUJ7FDJY149KNwf/qWKzCmlwNG8FUTyfGEIrLwPrkaM1z8y48fBtfJjSqtddEymJj4/CLmvI/j+SXVA1CXFpoaL62Hj8lHNQvBuizhvC8sTjrQpiO6Jvtir+5Ll0etHeR1jqOl9LkI7i8dwYZ3O5eEuj9r9mfB4BjNM/jACEYC97jrxqMruJhrvmedZfvzEKmoAj7RkdD1L8ckVl0pmf3qY6cE8QsoHiXbWNUz3RuMUga52MO+AdB0/TFSTFxZ6pfeeK/31hGH6Sq1o5ao6sQeEE/jnuPY3hHHn7w9xzHeNmRrVuvB8zOQdRi5iwIDAQAB\n-----END PUBLIC KEY-----'
AUTH_HEADER_NAME = 'Authorization'
ALLOWED_USER_ROLE = 'prothetic_user'
TOKEN_REALM_ACCESS = 'realm_access'
TOKEN_ROLES = 'roles'

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Функция проверяет, что переданный Access Token валидный и включает в себя переданную роль
#
def verifyRequestRights(authHeader, userRole):
    result = False
    try:
        # get token from bearer auth header
        token = authHeader.split()[1]
        app.logger.info('Token='+token);

        #verify token validity (signiture and expiry date) and get details
        decoded_payload = jwt.decode(token, KEYCLOAK_PUB_KEY, algorithms=[KEYCLOAK_TOKEN_ALG])

        #check if userRole is allowed by token
        tokenRoles = decoded_payload[TOKEN_REALM_ACCESS][TOKEN_ROLES]
        result = userRole in tokenRoles

        if result == False:
            app.logger.info('Token role is not allowed: '+tokenRoles.__str__());
    
        app.logger.info('Token details: '+decoded_payload.__str__());

    except IndexError:
        app.logger.info('Auth header do not include token: '+authHeader)

    except jwt.ExpiredSignatureError:
        app.logger.info('Token is outdated');

    except KeyError:
        app.logger.info('Token does not include role: '+decoded_payload.__str__());
    
    except Exception as e:
        app.logger.info('Unexpected error: '+e.__str__())

    finally:
        return result


# Функция обработчик Read (GET) сервиса /reports
#
#
@app.route('/')
@app.route('/reports', methods=['GET', 'OPTIONS'])
@cross_origin()
def reports():
    if verifyRequestRights(request.headers.get(AUTH_HEADER_NAME), ALLOWED_USER_ROLE):
        try:
            return send_from_directory(app.config['DOWNLOAD_FOLDER'], REPORT_FILE_NAME, as_attachment=True), 200
        
        except FileNotFoundError:
            app.logger.error('Report file is not found')
            return "File not found", 404
        
        except Exception as e:
            app.logger.error('Unexpected error: '+e.__str__())
    
    return 'User does not have access rights to report', 401

# Main entry point
#
#
if __name__ == '__main__':
   
     # Create the downloads directory if it doesn't exist
    if not os.path.exists(DOWNLOAD_FOLDER):
        os.makedirs(DOWNLOAD_FOLDER)

    # Create a dummy file for demonstration if it does not exist
    if not os.path.exists(DOWNLOAD_FOLDER+'/'+REPORT_FILE_NAME):
        with open(os.path.join(DOWNLOAD_FOLDER, REPORT_FILE_NAME), 'w') as f:
            f.write("Report data")
            f.close()

    app.run(debug=True, threaded=True, host='0.0.0.0', port=8000)
