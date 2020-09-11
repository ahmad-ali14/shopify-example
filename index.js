const dotenv = require("dotenv");
const express = require("express");
const app = express();
const crypto = require('crypto');
const cookie = require('cookie');
const nonce = require('nonce')();
const querystring = require('querystring');
const request = require('request-promise');
require('dotenv').config();

const apiKey = process.env.SHOPIFY_API_KEY;
const apiSecret = process.env.SHOPIFY_API_SECRET_KEY;

const scope = "write_products";
const ngrokForowardingAddress = "https://8f4ce15e7b4b.ngrok.io/";

app.get("/shopify", (req, res) => {
    const shop = req.query.shop;
    if(shop){
        const state = nonce();
        const redirectUri = ngrokForowardingAddress + "shopify/callback";
        const installUri = "https://" + shop +"/admin/oauth/authorize?client_id=" + apiKey + "&scope=" + scope + "&state=" + state + "&redirect_uri=" + redirectUri ;

        res.cookie("state", state);

        res.redirect(installUri);

    }else{
        res.status(400).send("missing shop parameter, please add ? shop=your-development-shop.shopify.com to your request");
    }
});


app.get("/shopify/callback",(req, res)=>{ 
    const { state, code, hmac, shop } = req.query;
    const stateCookie = cookie.parse(req.headers.cookie).state;

    if(state !== stateCookie){
        return res.status(403).send("request origin can not be verified");
    }

    if(shop && hmac && code){
        const map = Object.assign({}, req.query);
        delete map['hmac'];
        const message = querystring.stringify(map);
        const generatedHash = crypto.createHmac("sha256", apiSecret).update(message).digest('hex');

        if( generatedHash !== hmac){
            return res.status(400).send('Hmac validation error')
        }

       // res.status(200).send('Hmac valid');
       const accessTokenRequestUri = "https://" + shop + "/admin/oauth/access_token";
       const accessTokenPayload = {
           client_id: apiKey,
           client_secret: apiSecret,
           code
       }


       request.post(accessTokenRequestUri, {json: accessTokenPayload})
       .then((response)=>{ 
           const accessToken = response.access_token;
          // return res.status(200).send("Access Granted ...")
          const apiRequestUri = "https://" + shop + "/admin/shop.json";
          const apiRequestHeader = {
              "X-Shopify-Access-Token": accessToken
          };

          request.get(apiRequestUri, { headers:apiRequestHeader }).then((data)=>{ 
              res.end(data)
           }).catch(err => res.status(err.statusCode).send(err.error.error_description));
        
        }).catch(err =>
            {
                return  res.status(err.statusCode).send(err.error.error_description)
            })

    }

    else {
        res.status(400).send(' required parameter missing')
    }
})

app.listen(3000, ()=>{ console.log("shopify ...."); })