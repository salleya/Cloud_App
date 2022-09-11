# Cloud Application
Implements a REST API using proper resource based URLs, pagination, status codes, and user authorization.

# Application Requirements:

* An entity to model the User.

* At least two other non-user entities: Boats and Loads.

* The two non-user entities need to be related to each other.

* The user needs to be related to at least one of the non-user entities.

* Resources corresponding to the non-user entity related to the user must be protected.


# Non-User Entities:

* For each entity, a collection URL is provided that is represented by the collection name.  For example, GET /boats represents the boats collection.

* If an entity is related to a user, then the collection URL shows only those entities in the collection which are related to the user corresponding to the valid JWT provided in the request. For example, if each boat is owned by a user, then GET /boats only shows those entities that are owned by the user who is authenticated by the JWT supplied in the request.

* For an entity that is not related to users, the collection URL shows all the entities in the collection.

* The collection URL for an entity implements pagination showing 5 entities at a time. There is  a 'next' link on every page except the last. The collection includes a property that indicates how many total items are in the collection.

* Every representation of an entity has a 'self' link pointing to the canonical representation of that entity. This is a full URL, not a relative path.

* Each entity has at least 3 properties of its own. Id and self are not consider a property in this count.

* Every entity supports all 4 CRUD operations, i.e., create/add, read/get, update/edit and delete. Any "side effects" of these operations on an entity to other entities related to the entity are handled. For example, update loads when deleting a boat. Update for an entity supports both PUT and PATCH.

* Every CRUD operation for an entity related to a user is protected and requires a valid JWT corresponding to the relevant user.

* An endpoint to create a relationship and another to remove a relationship between the two non-user entities is provided. For example, endpoints to put a load on a boat and to remove a load from a boat are provided.

* If an entity has a relationship with other entities, then this info is displayed in the representation of the entity. For example, if a load is on a boat, then the representation of the boat shows the relationship with this load, and the representation of this load shows the relationship with this boat.

* For endpoints that require a request body, JSON representations are supported. 

* Response bodies are in JSON, including responses that contain an error message.

* Requests to an endpoint that will send back a response with a body include 'application/json' in the Accept header. If a request doesn't have such a header, it is rejected.


# User Entity:

* Supports the ability for users of the application to create user accounts.

* Uses Auth0 to handle user accounts.
 
* Requests for protected resources use a JWT for authentication. The JWT of the user and the user’s unique ID are shown after login.

* The value of “sub” from the JWT is used as the user’s unique ID.

* Provides an unprotected endpoint GET /users that returns all the users currently registered in the app, even if they don't currently have any relationship with a non-user entity.

# Status Codes

The following status codes are supported:

* 200 OK

* 201 Created

* 204 No Content

* 401 Unauthorized

* 403 Forbidden

* 405 Method Not Allowed

* 406 Not Acceptable 
