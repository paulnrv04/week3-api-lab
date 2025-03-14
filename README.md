# week3-api-lab

API (Application Programming Interface)
- is a set of rules and protocols that allows different software applications to communicate and exchange data with each other. APIs are commonly used in web and application development, where they define how a user requests and receives responses from a server using endpoints.

In this laboratory, it will showcase the initialization, create an entry point, testing the API endpoints, and simulation of microservices.

Initializing the API
- to set up the API Project, we must first create a folder on the desktop and initialize it using Node.js. Open the folder on VSCode to run a terminal and run ‘npm init -y’ to generate a package.json file. Next, we must also install the required packages by typing ‘npm install express jsonwebtoken bcryptjs body-parser nodemon dotenv’ which are essential for handling authentication and the request process.

Creating and Setting Up server.js
- The server.js file created will serve as the entry point for the API. It initializes an Express server, holds the routes for handling user authentication using ‘username’ and ‘password’ in the registration and log in. The packages installed are implemented in the body wherein body-parser is used to parse the incoming JSON data, while jsonwebtoken and bcryptjs manages the authentication by securely hashing the password and generating JWT tokens for user sessions.

Usage of Postman to Test the API endpoints
- Postman is used to test the API endpoints by sending HTTP methods/requests and verifying responses. The process includes registration via POST /api/register, logging in with POST /api/login, and accessing protected routes using a valid JWT token in the authorization header. It ensures that the API does its job correctly before integrating it with a frontend or other services.

Simulation of Microservices (Authentication and Product)
- To implement the microservices, the two management systems are split into two separate services. The auth-service.js handles the user registration, login, and token verification, ensuring secure access to protected routes (this is the same process as the server.js). On the other hand, product-service.js manages the product catalog, which can handle operations such as adding and retrieving products.
