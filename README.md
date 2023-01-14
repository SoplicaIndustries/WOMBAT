
# Wombat Identity API

Wombat is a Identity Login/Register service developed in .NET 6.0 using Entity Framework with Identity.
API authentication provides your client user with JSON Web Token, which can be later used for authorization.





## Authors

- [@Jack Soplica](https://www.github.com/SoplicaIndustries)


## What this API provides?
    1. User creation and login
    2. Email confirmation for important actions
    3. User authentication and authorization

## App settings configuration
    1. Database details
        a) Provide your connection string
    2. JSON Web Token
        a) Provide valid token issuer (API url)
        b) Provide valid token audience (your application)
        c) Provide your secret JWT key
        d) Set dbmode to true/false (read more to learn about dbmode)
    3. Mail service
        a) Provide mail address that will be used for sending mail to users
        b) Provide mail password/application password
        c) Provide your smtp server details (server, port)
        d) Provide urls for forms in your application (email confirmation screen, change mail confirmation, password change form)
    4. API key
        a) Provide key that will be used to authorize access of your application 

## Database configuration
    1. add migration and update database (using regular Entity framework commands)
    2. Database should have following scheduled events:
        a) Expired token cleaning every 1 day (if dbmode is set to true)
        b) Unconfirmed user cleaning every 3 hours
## Documentation
https://documenter.getpostman.com/view/19462677/2s8ZDR6jzR
        
