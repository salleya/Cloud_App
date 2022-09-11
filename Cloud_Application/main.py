##########################################################################
#
# Amy Salley
# 5 June 2022
#
##########################################################################

from google.cloud import datastore
from flask import Flask, request, make_response, render_template
import json
import requests
import constants
from functools import wraps
from six.moves.urllib.request import urlopen
from flask_cors import cross_origin
from jose import jwt

from os import environ as env
from werkzeug.exceptions import HTTPException
from dotenv import load_dotenv, find_dotenv

from flask import jsonify
from flask import redirect
from flask import session
from flask import url_for
from authlib.integrations.flask_client import OAuth
from six.moves.urllib.parse import urlencode
from urllib.parse import quote_plus, urlencode

app = Flask(__name__)

app.secret_key = "SECRET_KEY"
client = datastore.Client()

BOATS = "boats"
LOADS = "loads"
USERS = "users"


# Update the values of the following 3 variables
CLIENT_ID = 'wjJLseE5FJkwWY1J7p6yVgCEzmppZKQL'
CLIENT_SECRET = '2wrXI2P78g_RHOqDSMdUag2-HRqV8CEpCSTWtDdQypAc3HFEowBtLq3rZOLtsJuO'
DOMAIN = 'cs493-hw7-sal.us.auth0.com'
# For example
# DOMAIN = 'fall21.us.auth0.com'

ALGORITHMS = ["RS256"]

oauth = OAuth(app)

auth0 = oauth.register(
    'auth0',
    client_id=CLIENT_ID,
    client_secret=CLIENT_SECRET,
    api_base_url="https://" + DOMAIN,
    access_token_url="https://" + DOMAIN + "/oauth/token",
    authorize_url="https://" + DOMAIN + "/authorize",
    client_kwargs={
        'scope': 'openid profile email',
    },
    server_metadata_url="https://" + DOMAIN + "/.well-known/openid-configuration",
)


# This code is adapted from https://auth0.com/docs/quickstart/backend/python/01-authorization?_ga=2.46956069.349333901.1589042886-466012638.1589042885#create-the-jwt-validation-decorator

class AuthError(Exception):
    def __init__(self, error, status_code):
        self.error = error
        self.status_code = status_code


@app.errorhandler(AuthError)
def handle_auth_error(ex):
    response = jsonify(ex.error)
    response.status_code = ex.status_code
    return response

# Verify the JWT in the request's Authorization header
def verify_jwt(request):
    if 'Authorization' in request.headers:
        auth_header = request.headers['Authorization'].split()
        token = auth_header[1]
    else:
        raise AuthError({"code": "no auth header",
                            "description":
                                "Authorization header is missing"}, 401)
    
    jsonurl = urlopen("https://"+ DOMAIN+"/.well-known/jwks.json")
    jwks = json.loads(jsonurl.read())
    try:
        unverified_header = jwt.get_unverified_header(token)
    except jwt.JWTError:
        raise AuthError({"code": "invalid_header",
                        "description":
                            "Invalid header. "
                            "Use an RS256 signed JWT Access Token"}, 401)
    if unverified_header["alg"] == "HS256":
        raise AuthError({"code": "invalid_header",
                        "description":
                            "Invalid header. "
                            "Use an RS256 signed JWT Access Token"}, 401)
    rsa_key = {}
    for key in jwks["keys"]:
        if key["kid"] == unverified_header["kid"]:
            rsa_key = {
                "kty": key["kty"],
                "kid": key["kid"],
                "use": key["use"],
                "n": key["n"],
                "e": key["e"]
            }
    if rsa_key:
        try:
            payload = jwt.decode(
                token,
                rsa_key,
                algorithms=ALGORITHMS,
                audience=CLIENT_ID,
                issuer="https://"+ DOMAIN+"/"
            )
        except jwt.ExpiredSignatureError:
            raise AuthError({"code": "token_expired",
                            "description": "token is expired"}, 401)
        except jwt.JWTClaimsError:
            raise AuthError({"code": "invalid_claims",
                            "description":
                                "incorrect claims,"
                                " please check the audience and issuer"}, 401)
        except Exception:
            raise AuthError({"code": "invalid_header",
                            "description":
                                "Unable to parse authentication"
                                " token."}, 401)

        return payload
    else:
        raise AuthError({"code": "no_rsa_key",
                            "description":
                                "No RSA key in JWKS"}, 401)


@app.route('/')
def index():
    
    userExists = session.get("user")

    if userExists:
        addUser = True

        # See if user is in the database
        query = client.query(kind=constants.users)
        results = list(query.fetch())
        if results:
            for e in results:
                if e["unique_id"] == userExists["userinfo"]["sub"]:
                    addUser = False

        # Add new user if necessary
        if addUser:
            new_user = datastore.entity.Entity(key=client.key(constants.users))
            new_user.update({"name": userExists["userinfo"]["name"], "unique_id": userExists["userinfo"]["sub"]})
            client.put(new_user)
        

    return render_template(
        'index.html', 
        session=session.get("user"),
        userInfo=json.dumps(session.get("user"), indent=4),
        )
        
#######################
# Users
#######################
@app.route('/users', methods=['GET', 'POST'])
def users_get():

    # Display all users
    if request.method == 'GET':
        query = client.query(kind=constants.users)
        results = list(query.fetch()) 
        res = make_response(json.dumps(results))
        res.mimetype = 'application/json'
        res.status_code = 200
        return res
    
    else:
        return (json.dumps({"Error": "Method not allowed"}), 405)


#######################
# Boats
#######################

# Boats, POST and GET
@app.route('/boats', methods=['POST','GET', 'DELETE'])
def boats_get_post():

    # Create a new boat
    if request.method == 'POST':

        # Check Accept header
        if 'application/json' not in request.accept_mimetypes:
            return (json.dumps({"Error": "Client must accept JSON response"}), 406)

        payload = verify_jwt(request)
        content = request.get_json()

        # Verify all attributes are included
        if "name" in content and "type" in content and "length" in content:

            # Create the new boat
            new_boat = datastore.entity.Entity(key=client.key(constants.boats))
            new_boat.update({"name": content["name"], "type": content["type"],
                "length": int(content["length"]), "owner": payload["sub"], "loads": []})
            client.put(new_boat)

            new_boat["id"] = int(new_boat.key.id)
            new_boat["self"] = request.base_url + '/' + str(new_boat.key.id)

            res = make_response(json.dumps(new_boat))
            res.mimetype = 'application/json'
            res.status_code = 201
            return res
            
        else:
            return (json.dumps({"Error": "The request object is missing at least one of the required attributes"}), 400)

    # Display boats
    elif request.method == 'GET':

        # Check Accept header
        if 'application/json' not in request.accept_mimetypes:
            return (json.dumps({"Error": "Client must accept JSON response"}), 406)
        
        # Display boats of user
        try:
            payload = verify_jwt(request)
            query = client.query(kind=constants.boats)

            # Add filter to return only the user's boats
            query.add_filter("owner", "=", payload["sub"])
            total_items = len(list(query.fetch()))

            # Implement pagination to return 5 boats per page
            q_limit = int(request.args.get('limit', '5'))
            q_offset = int(request.args.get('offset', '0'))
            l_iterator = query.fetch(limit = q_limit, offset = q_offset)
            pages = l_iterator.pages
            results = list(next(pages))

            # Create the "next" URL
            if l_iterator.next_page_token:
                next_offset = q_offset + q_limit
                next_url = request.base_url + "?limit=" + str(q_limit) + "&offset=" + str(next_offset)
            else:
                next_url = None

            # Include "id" and "self" in the response
            for e in results:
                e["id"] = e.key.id
                e["self"] = request.host_url + 'boats/' + str(e.key.id)
            output = {"boats": results}

            output["total_items"] = total_items

            if next_url:
                output["next"] = next_url
            
            res = make_response(json.dumps(output))
            res.mimetype = 'application/json'
            res.status_code = 200
            return res  

        # Invalid/missing JWT
        except:
            return (json.dumps({"Error": "Unauthorized"}), 401)
    
    else:
        return (json.dumps({"Error": "Method not allowed"}), 405)

# Boats, PUT, PATCH DELETE, and GET specific boat
@app.route('/boats/<id>', methods=['PUT', 'PATCH', 'DELETE', 'GET'])
def boats_put_delete(id):

    # Edit data for a specfic boat using PUT method
    if request.method == 'PUT':

        # Check Accept header
        if 'application/json' not in request.accept_mimetypes:
            return (json.dumps({"Error": "Client must accept JSON response"}), 406)

        payload = verify_jwt(request)
        content = request.get_json()

        if "name" in content and "type" in content and "length" in content:
            boat_key = client.key(constants.boats, int(id))
            boat = client.get(key=boat_key)
            if boat:
                # Verify user is the boat owner
                if payload["sub"] != boat["owner"]:
                    return (json.dumps({"Error": "Only the boat owner may edit this boat"}), 403)

                boat.update({"name": content["name"], "type": content["type"],
                    "length": int(content["length"]), "loads": []})
                client.put(boat)

                boat["id"] = int(id)
                boat["self"] = request.host_url + 'boats/' + str(id)

                res = make_response(json.dumps(boat))
                res.mimetype = 'application/json'
                res.status_code = 200
                return res
                
            else:
                return (json.dumps({"Error": "No boat with this boat_id exists"}), 404)
        else:
            return (json.dumps({"Error": "The request object is missing at least one of the required attributes"}), 400)
    

    # Edit data for specific boat using PATCH method
    if request.method == 'PATCH':

        # Check Accept header
        if 'application/json' not in request.accept_mimetypes:
            return (json.dumps({"Error": "Client must accept JSON response"}), 406)

        payload = verify_jwt(request)
        content = request.get_json()
        boat_key = client.key(constants.boats, int(id))
        boat = client.get(key=boat_key)
        
        if boat:
            # Verify user is the boat owner
            if payload["sub"] != boat["owner"]:
                return (json.dumps({"Error": "Only the boat owner may edit this boat"}), 403)
        
            # Edit the boat name
            if "name" in content:
                boat.update({"name": content["name"]})
            
            # Edit the boat type
            if "type" in content:
                boat.update({"type": content["type"]})

            # Edit the boat length
            if "length" in content:
                boat.update({"length": int(content["length"])})
                
            client.put(boat)
            boat["id"] = int(id)
            boat["self"] = request.host_url + 'boats/' + str(id)

            res = make_response(json.dumps(boat))
            res.mimetype = 'application/json'
            res.status_code = 200
            return res
            
        else:
            return (json.dumps({"Error": "No boat with this boat_id exists"}), 404)
        

    # Delete a specific boat
    if request.method == 'DELETE':
        payload = verify_jwt(request)
        boat_key = client.key(constants.boats, int(id))
        boat = client.get(key=boat_key)
        if boat:
            if payload["sub"] != boat["owner"]:
                return (json.dumps({"Error": "Only the boat owner may delete this boat"}), 403)

            else:
                client.delete(boat_key)

                # If the boat was carrying a load, remove the boat
                # from the load carrier attribute (unload the load)
                query = client.query(kind=constants.loads)
                results = list(query.fetch())

                for e in results:
                    if e["carrier"]:
                        if e["carrier"] == int(id):
                            e.update({"carrier": None})
                            client.put(e)

                return ('', 204)
        else:
            return (json.dumps({"Error": "No boat with this boat_id exists"}), 404)


    # Get data for a specific boat
    elif request.method == 'GET':

        # Check Accept header
        if 'application/json' not in request.accept_mimetypes:
            return (json.dumps({"Error": "Client must accept JSON response"}), 406)

        payload = verify_jwt(request)
        boat_key = client.key(constants.boats, int(id))
        boat = client.get(key=boat_key)
        if boat:
            if payload["sub"] != boat["owner"]:
                return (json.dumps({"Error": "Only the boat owner may view this boat"}), 403)

            boat["id"] = int(id)
            boat["self"] = request.host_url + 'boats/' + str(id)

            res = make_response(json.dumps(boat))
            res.mimetype = 'application/json'
            res.status_code = 200
            return res
    
        else:
            return (json.dumps({"Error": "No boat with this boat_id exists"}), 404)

    else:
        return (json.dumps({"Error": "Method not allowed."}), 405)

#############################
# Loads
#############################

# Loads, POST and GET
@app.route('/loads', methods=['POST','GET'])
def loads_get_post():

    # Create a new load
    if request.method == 'POST':

        # Check Accept header
        if 'application/json' not in request.accept_mimetypes:
            return (json.dumps({"Error": "Client must accept JSON response"}), 406)

        content = request.get_json()

        # Verify all required attributes are included
        if "volume" in content and "item" in content and "creation_date" in content:
            new_load = datastore.entity.Entity(key=client.key(constants.loads))
            new_load.update({"volume": int(content["volume"]), "carrier": None, "item": content["item"],
                "creation_date": content["creation_date"]})
            client.put(new_load)

            # Include "id" and "self" in response
            new_load["id"] = int(new_load.key.id)
            new_load["self"] = request.base_url + '/' + str(new_load["id"])
            
            res = make_response(json.dumps(new_load))
            res.mimetype = 'application/json'
            res.status_code = 201
            return res

        else:
            return (json.dumps({"Error": "The request object is missing at least one of the required attributes"}), 400)

    # Get all loads
    elif request.method == 'GET':

        # Check Accept header
        if 'application/json' not in request.accept_mimetypes:
            return (json.dumps({"Error": "Client must accept JSON response"}), 406)

        query = client.query(kind=constants.loads)
        total_items = len(list(query.fetch()))

        # Implement pagination to return 5 loads per page
        q_limit = int(request.args.get('limit', '5'))
        q_offset = int(request.args.get('offset', '0'))
        l_iterator = query.fetch(limit= q_limit, offset=q_offset)
        pages = l_iterator.pages
        results = list(next(pages))

        # Create the "next" URL
        if l_iterator.next_page_token:
            next_offset = q_offset + q_limit
            next_url = request.base_url + "?limit=" + str(q_limit) + "&offset=" + str(next_offset)
        else:
            next_url = None

        # Include "id" and "self" in the response
        for e in results:
            e["id"] = int(e.key.id)
            e["self"] = request.host_url + 'loads/' + str(e.key.id)
            print(e["self"])

        output = {"loads": results}
        output["total_items"] = total_items

        if next_url:
            output["next"] = next_url

        res = make_response(json.dumps(output))
        res.mimetype = 'application/json'
        res.status_code = 200
        return res

    else:
        return 'Method not recognized'


# Loads, PUT, PATCH, DELETE and GET a specific load
@app.route('/loads/<id>', methods=['PUT','PATCH','DELETE','GET'])
def loads_get_delete(id):

    # Edit data for a specfic load using PUT method
    if request.method == 'PUT':

        # Check Accept header
        if 'application/json' not in request.accept_mimetypes:
            return (json.dumps({"Error": "Client must accept JSON response"}), 406)

        content = request.get_json()

        if "volume" in content and "item" in content and "creation_date" in content:
            load_key = client.key(constants.loads, int(id))
            load = client.get(key=load_key)
            if load:
                
                load.update({"item": content["item"], "volume": int(content["volume"]),
                    "creation_date": content["creation_date"], "carrier": None})
                client.put(load)

                load["id"] = int(id)
                load["self"] = request.host_url + 'loads/' + str(id)

                res = make_response(json.dumps(load))
                res.mimetype = 'application/json'
                res.status_code = 200
                return res
                
            else:
                return (json.dumps({"Error": "No load with this load_id exists"}), 404)
        else:
            return (json.dumps({"Error": "The request object is missing at least one of the required attributes"}), 400)
    

    # Edit data for specific load using PATCH method
    if request.method == 'PATCH':

        # Check Accept header
        if 'application/json' not in request.accept_mimetypes:
            return (json.dumps({"Error": "Client must accept JSON response"}), 406)

        content = request.get_json()
        load_key = client.key(constants.loads, int(id))
        load = client.get(key=load_key)
        
        if load:
            
            # Edit the load item
            if "item" in content:
                load.update({"item": content["item"]})
            
            # Edit the load volume
            if "volume" in content:
                load.update({"volume": int(content["volume"])})

            # Edit the load creation date
            if "creation_date" in content:
                load.update({"creation_date": content["creation_date"]})
                
            client.put(load)
            load["id"] = int(id)
            load["self"] = request.host_url + 'loads/' + str(id)

            res = make_response(json.dumps(load))
            res.mimetype = 'application/json'
            res.status_code = 200
            return res
            
        else:
            return (json.dumps({"Error": "No load with this load_id exists"}), 404)
    

    # Delete a specific load
    elif request.method == 'DELETE':
        load_key = client.key(constants.loads, int(id))
        load = client.get(key=load_key)
        if load:
            client.delete(load_key)

            # Update the boat loads attribute to remove load
            query = client.query(kind=constants.boats)
            results = list(query.fetch())

            new_loads = []
            for e in results:
                end_index = len(e["loads"])
                for i in range(0, end_index):
                    if int(e["loads"][i]) != int(id):
                        new_loads.append(e["loads"][i])
                e.update({"loads": new_loads})
                client.put(e)

            return ('', 204)
        else:
            return (json.dumps({"Error": "No load with this load_id exists"}), 404)


    # Get a specific load
    elif request.method == 'GET':

        # Check Accept header
        if 'application/json' not in request.accept_mimetypes:
            return (json.dumps({"Error": "Client must accept JSON response"}), 406)
            
        load_key = client.key(constants.loads, int(id))
        load = client.get(key=load_key)
        if load:
            load["id"] = int(id)
            load["self"] = request.host_url + 'loads/' + str(id)

            res = make_response(json.dumps(load))
            res.mimetype = 'application/json'
            res.status_code = 200
            return res
            
        else:
            return (json.dumps({"Error": "No load with this load_id exists"}), 404)

    else:
        return 'Method not recognized'


#####################
# Loads on Boats
#####################

# Loads on boats, PUT and DELETE
@app.route('/boats/<boat_id>/loads/<load_id>', methods=['PUT', 'DELETE'])
def loads_put_delete(boat_id, load_id):

    # Assign a load to a boat
    if request.method == 'PUT':
    
        boat_key = client.key(constants.boats, int(boat_id))
        boat = client.get(key=boat_key)

        load_key = client.key(constants.loads, int(load_id))
        load = client.get(key=load_key)

        if boat and load:

            if load["carrier"] is not None:
                return (json.dumps({"Error": "The load is already loaded on another boat"}), 403)

            load.update({"carrier": int(boat_id)})
            client.put(load)

            load_to_add = int(load_id)
            boat["loads"].append(load_to_add)
            client.put(boat)

            return ('', 204)
        else:
            return (json.dumps({"Error": "The specified boat and/or load does not exist"}), 404)
    
    # Remove a load from a boat
    elif request.method == 'DELETE':
    
        boat_key = client.key(constants.boats, int(boat_id))
        boat = client.get(key=boat_key)

        load_key = client.key(constants.loads, int(load_id))
        load = client.get(key=load_key)

        if boat and load:
            if load["carrier"] is None:
                return (json.dumps({"Error": "No boat with this boat_id is loaded with the load with this load_id"}), 404)

            if load["carrier"] == int(boat_id):
                load.update({"carrier": None})
                client.put(load)

                list_of_loads = []

                for i in range(0, len(boat["loads"])):
                    if int(boat["loads"][i]) != int(load_id):
                        list_of_loads.append(boat["loads"][i])
                boat.update({"loads": list_of_loads})
                client.put(boat)
                
                return ('', 204)
            else:
                return (json.dumps({"Error": "No boat with this boat_id is loaded with the load with this load_id"}), 404)
            
        else:
            return (json.dumps({"Error": "No boat with this boat_id is loaded with the load with this load_id"}), 404)

    else:
        return 'Method not recognized'


#############################
# JWT
#############################

# Decode the JWT supplied in the Authorization header
@app.route('/decode', methods=['GET'])
def decode_jwt():
    payload = verify_jwt(request)
    return payload        


# Generate a JWT from the Auth0 domain and return it
# Request: JSON body with 2 properties with "username" and "password"
#       of a user registered with this Auth0 domain
# Response: JSON with the JWT as the value of the property id_token
@app.route('/login', methods=['GET', 'POST'])
def login_user():
    if request.method == 'GET':
        return oauth.auth0.authorize_redirect(
            redirect_uri=url_for("callback", _external=True)
        )

    elif request.method == 'POST':
        content = request.get_json()
        username = content["username"]
        password = content["password"]
        body = {'grant_type':'password',
            'username':username,
            'password':password,
            'client_id':CLIENT_ID,
            'client_secret':CLIENT_SECRET
           }
        headers = { 'content-type': 'application/json' }
        url = 'https://' + DOMAIN + '/oauth/token'
        r = requests.post(url, json=body, headers=headers)
        return r.text, 200, {'Content-Type':'application/json'}


@app.route("/callback", methods=["GET", "POST"])
def callback():
    token = oauth.auth0.authorize_access_token()
    session["user"] = token
    return redirect("/")

@app.route("/logout")
def logout():
    session.clear()
    return redirect(
        "https://" + DOMAIN + "/v2/logout?"
        + urlencode(
            {
                "returnTo": url_for("index", _external=True),
                "client_id": CLIENT_ID,
            },
            quote_via=quote_plus,
        )
    )

if __name__ == '__main__':
    app.run(host='127.0.0.1', port=8080, debug=True)