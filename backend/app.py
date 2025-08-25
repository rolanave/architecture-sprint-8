import logging
import os
from flask import Flask, request, send_from_directory
from flask_cors import CORS, cross_origin
import jwt
import requests
from cryptography.x509 import load_pem_x509_certificate
from cryptography.hazmat.primitives import serialization

app = Flask(__name__)
cors = CORS(app)
app.config['CORS_HEADERS'] = 'Content-Type'
app.config['KEYCLOAK_PUB_KEY'] = b''

DOWNLOAD_FOLDER = '/app/download'
app.config['DOWNLOAD_FOLDER'] = DOWNLOAD_FOLDER


REPORT_FILE_NAME = 'report.txt'
KEYCLOAK_TOKEN_ALG = 'RS256'
AUTH_HEADER_NAME = 'Authorization'
ALLOWED_USER_ROLE = 'prothetic_user'
TOKEN_REALM_ACCESS = 'realm_access'
TOKEN_ROLES = 'roles'
KEYCLOAK_URL = 'http://keycloak:8080'
KEYCLOAK_REALM = 'reports-realm'
KEYCLOAK_CERTS_PATH = '/realms/'+KEYCLOAK_REALM+'/protocol/openid-connect/certs'

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Функция загружает сертификаты из кейклоака и пытается собрать публичный ключ для RSA
#
#
def getKeycloakPubKey ():
    try:
        response = requests.get(KEYCLOAK_URL+KEYCLOAK_CERTS_PATH).json()
        kcKeys = response['keys']

        if kcKeys == '':
            raise Exception('Could not obtain keys from keycloak: '+response.__str__())
        
        rsa_cert = ''
        for key in kcKeys:
            if key['alg'] == KEYCLOAK_TOKEN_ALG:
                rsa_cert = key['x5c'][0]
                break
    
        if rsa_cert == '':
            raise Exception('No public key for RSA: '+kcKeys.__str__())
    
        formattedCert = '-----BEGIN CERTIFICATE-----\n'+rsa_cert+'\n-----END CERTIFICATE-----\n'

        cert_obj = load_pem_x509_certificate(formattedCert.encode(encoding="utf-8"))
        public_key = cert_obj.public_key()
        public_pem = public_key.public_bytes(encoding=serialization.Encoding.PEM,format=serialization.PublicFormat.SubjectPublicKeyInfo)

    except Exception as e:
        app.logger.error('Error: '+e.__str__()+'\nOriginal request: '+response.__str__())
        return b''
    
    else:
        app.logger.info('RSA pub key: ' + public_pem.__str__())
        return public_pem;


# Функция проверяет, что переданный Access Token валидный и включает в себя переданную роль
#
def verifyRequestRights(authHeader, userRole):
    result = False
    try:
        if authHeader == None:
            raise Exception("Auth header is empty")
        
        # get token from bearer auth header
        token = authHeader.split()[1]
        app.logger.info('Token='+token);

        #verify token validity (signiture and expiry date) and get details
        decoded_payload = jwt.decode(token, app.config['KEYCLOAK_PUB_KEY'], algorithms=[KEYCLOAK_TOKEN_ALG])

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
        app.logger.info('Error: '+e.__str__())

    finally:
        return result


# Функция обработчик Read (GET) сервиса /reports
#
#
@app.route('/')
@app.route('/reports', methods=['GET', 'OPTIONS'])
@cross_origin()
def reports():
    if app.config['KEYCLOAK_PUB_KEY'] == b'':
        #
        # Lazy initialization of public key
        #
        app.logger.info('Attempt to download public keys from keycloak')
        app.config['KEYCLOAK_PUB_KEY'] = getKeycloakPubKey()

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
