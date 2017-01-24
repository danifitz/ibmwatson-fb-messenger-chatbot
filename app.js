/*
 * Copyright 2016-present, Facebook, Inc.
 * All rights reserved.
 *
 * This source code is licensed under the license found in the
 * LICENSE file in the root directory of this source tree.
 *
 */

/* jshint node: true, devel: true */
'use strict';

const
    bodyParser = require('body-parser'),
    config = require('config'),
    crypto = require('crypto'),
    express = require('express'),
    https = require('https'),
    request = require('request'),
    conversationv1 = require('watson-developer-cloud/conversation/v1'),
    Promise = require('bluebird'),
    colors = require('colors');

var app = express();
app.set('port', process.env.PORT || 5000);
app.set('view engine', 'ejs');
app.use(bodyParser.json({ verify: verifyRequestSignature }));
app.use(express.static('public'));

/*
 * Be sure to setup your config values before running this code. You can
 * set them using environment variables or modifying the config file in /config.
 *
 */

// App Secret can be retrieved from the App Dashboard
const APP_SECRET = (process.env.MESSENGER_APP_SECRET) ?
  process.env.MESSENGER_APP_SECRET :
  config.get('appSecret');

// Arbitrary value used to validate a webhook
const VALIDATION_TOKEN = (process.env.MESSENGER_VALIDATION_TOKEN) ?
  (process.env.MESSENGER_VALIDATION_TOKEN) :
  config.get('validationToken');

// Generate a page access token for your page from the App Dashboard
const PAGE_ACCESS_TOKEN = (process.env.MESSENGER_PAGE_ACCESS_TOKEN) ?
  (process.env.MESSENGER_PAGE_ACCESS_TOKEN) :
  config.get('pageAccessToken');

// URL where the app is running (include protocol). Used to point to scripts and
// assets located at this address.
const SERVER_URL = (process.env.SERVER_URL) ?
  (process.env.SERVER_URL) :
  config.get('serverURL');

const CONV_URL = config.get('conversationUrl');
const CONV_USER = config.get('conversationUsername');
const CONV_PASSWORD = config.get('conversationPassword');
const CONV_WORKSPACE = config.get('conversationWorkspace');
const API_KEY = config.get('API_Key');
const API_SECRET = config.get('API_Secret');

if (!(APP_SECRET && VALIDATION_TOKEN && PAGE_ACCESS_TOKEN && SERVER_URL
&& CONV_URL && CONV_USER && CONV_PASSWORD && CONV_WORKSPACE)) {
  console.error("Missing config values");
  process.exit(1);
}

// Set up Watson Conversation service wrapper.
const conversation = new conversationv1({
  username: CONV_USER, // replace with username from service key
  password: CONV_PASSWORD, // replace with password from service key
  path: { workspace_id: CONV_WORKSPACE }, // replace with workspace ID
  version_date: '2016-07-11'
});

// Used to store the conversation context
let currentContext = {};

const currentAccountActions = {
  insurance: 'mobile_insurance',
  interest: 'interest',
  cashback: 'cashback'
};

// Find a context by User ID
function findContextByUserID(userID) {
  for(let i = 0; i < currentContext.length; i++) {
    let context = currentContext[i];
    if(context.userID === userID) {
      return context;
    } else {
      return undefined;
    }
  }
}

/*
 * Use your own validation token. Check that the token used in the Webhook
 * setup is the same token used here.
 *
 */
app.get('/webhook', function(req, res) {
  if (req.query['hub.mode'] === 'subscribe' &&
      req.query['hub.verify_token'] === VALIDATION_TOKEN) {
    console.log("Validating webhook");
    res.status(200).send(req.query['hub.challenge']);
  } else {
    console.error("Failed validation. Make sure the validation tokens match.");
    res.sendStatus(403);
  }
});


/*
 * All callbacks for Messenger are POST-ed. They will be sent to the same
 * webhook. Be sure to subscribe your app to your page to receive callbacks
 * for your page.
 * https://developers.facebook.com/docs/messenger-platform/product-overview/setup#subscribe_app
 *
 */
app.post('/webhook', function (req, res) {
  var data = req.body;

  // Make sure this is a page subscription
  if (data.object == 'page') {
    // Iterate over each entry
    // There may be multiple if batched
    data.entry.forEach(function(pageEntry) {
      var pageID = pageEntry.id;
      var timeOfEvent = pageEntry.time;

      // Iterate over each messaging event
      pageEntry.messaging.forEach(function(messagingEvent) {
        if (messagingEvent.optin) {
          receivedAuthentication(messagingEvent);
        } else if (messagingEvent.message) {
          receivedMessage(messagingEvent);
        } else if (messagingEvent.delivery) {
          receivedDeliveryConfirmation(messagingEvent);
        } else if (messagingEvent.postback) {
          receivedPostback(messagingEvent);
        } else if (messagingEvent.read) {
          receivedMessageRead(messagingEvent);
        } else if (messagingEvent.account_linking) {
          receivedAccountLink(messagingEvent);
        } else {
          console.log("Webhook received unknown messagingEvent: ", messagingEvent);
        }
      });
    });

    // Assume all went well.
    //
    // You must send back a 200, within 20 seconds, to let us know you've
    // successfully received the callback. Otherwise, the request will time out.
    res.sendStatus(200);
  }
});

/*
 * This path is used for account linking. The account linking call-to-action
 * (sendAccountLinking) is pointed to this URL.
 *
 */
app.get('/authorize', function(req, res) {
  var accountLinkingToken = req.query.account_linking_token;
  var redirectURI = req.query.redirect_uri;

  // Authorization Code should be generated per user by the developer. This will
  // be passed to the Account Linking callback.
  var authCode = "1234567890";

  // Redirect users to this URI on successful login
  var redirectURISuccess = redirectURI + "&authorization_code=" + authCode;

  res.render('authorize', {
    accountLinkingToken: accountLinkingToken,
    redirectURI: redirectURI,
    redirectURISuccess: redirectURISuccess
  });
});

/*
 * Verify that the callback came from Facebook. Using the App Secret from
 * the App Dashboard, we can verify the signature that is sent with each
 * callback in the x-hub-signature field, located in the header.
 *
 * https://developers.facebook.com/docs/graph-api/webhooks#setup
 *
 */
function verifyRequestSignature(req, res, buf) {
  var signature = req.headers["x-hub-signature"];

  if (!signature) {
    // For testing, let's log an error. In production, you should throw an
    // error.
    console.error("Couldn't validate the signature.");
  } else {
    var elements = signature.split('=');
    var method = elements[0];
    var signatureHash = elements[1];

    var expectedHash = crypto.createHmac('sha1', APP_SECRET)
                        .update(buf)
                        .digest('hex');

    if (signatureHash != expectedHash) {
      throw new Error("Couldn't validate the request signature.");
    }
  }
}

/*
 * Authorization Event
 *
 * The value for 'optin.ref' is defined in the entry point. For the "Send to
 * Messenger" plugin, it is the 'data-ref' field. Read more at
 * https://developers.facebook.com/docs/messenger-platform/webhook-reference/authentication
 *
 */
function receivedAuthentication(event) {
  var senderID = event.sender.id;
  var recipientID = event.recipient.id;
  var timeOfAuth = event.timestamp;

  // The 'ref' field is set in the 'Send to Messenger' plugin, in the 'data-ref'
  // The developer can set this to an arbitrary value to associate the
  // authentication callback with the 'Send to Messenger' click event. This is
  // a way to do account linking when the user clicks the 'Send to Messenger'
  // plugin.
  var passThroughParam = event.optin.ref;

  console.log("Received authentication for user %d and page %d with pass " +
    "through param '%s' at %d", senderID, recipientID, passThroughParam,
    timeOfAuth);

  // When an authentication is received, we'll send a message back to the sender
  // to let them know it was successful.
  sendTextMessage(senderID, "Authentication successful");
}

/*
 * Message Event
 *
 * This event is called when a message is sent to your page. The 'message'
 * object format can vary depending on the kind of message that was received.
 * Read more at https://developers.facebook.com/docs/messenger-platform/webhook-reference/message-received
 *
 * For this example, we're going to echo any text that we get. If we get some
 * special keywords ('button', 'generic', 'receipt'), then we'll send back
 * examples of those bubbles to illustrate the special message bubbles we've
 * created. If we receive a message with an attachment (image, video, audio),
 * then we'll simply confirm that we've received the attachment.
 *
 */
function receivedMessage(event) {
  var senderID = event.sender.id;
  var recipientID = event.recipient.id;
  var timeOfMessage = event.timestamp;
  var message = event.message;

  console.log("Received message for user %d and page %d at %d with message:",
    senderID, recipientID, timeOfMessage);
  console.log(JSON.stringify(message));

  var isEcho = message.is_echo;
  var messageId = message.mid;
  var appId = message.app_id;
  var metadata = message.metadata;

  // You may get a text or attachment but not both
  var messageText = message.text;
  var messageAttachments = message.attachments;
  var quickReply = message.quick_reply;

  if (isEcho) {
    // Just logging message echoes to console
    console.log("Received echo for message %s and app %d with metadata %s",
      messageId, appId, metadata);
    return;
  } else if (quickReply) {
    var quickReplyPayload = quickReply.payload;
    console.log("Quick reply for message %s with payload %s",
      messageId, quickReplyPayload);

    sendTextMessage(senderID, "Quick reply tapped");
    return;
  }

  if (messageText) {

    // If we receive a text message, check to see if it matches any special
    // keywords and send back the corresponding example. Otherwise, just echo
    // the text we received.
    switch (messageText) {
      case 'image':
        sendImageMessage(senderID);
        break;

      case 'gif':
        sendGifMessage(senderID);
        break;

      case 'audio':
        sendAudioMessage(senderID);
        break;

      case 'video':
        sendVideoMessage(senderID);
        break;

      case 'file':
        sendFileMessage(senderID);
        break;

      case 'button':
        sendButtonMessage(senderID);
        break;

      case 'generic':
        sendGenericMessage(senderID);
        break;

      case 'receipt':
        sendReceiptMessage(senderID);
        break;

      case 'quick reply':
        sendQuickReply(senderID);
        break;

      case 'read receipt':
        sendReadReceipt(senderID);
        break;

      case 'typing on':
        sendTypingOn(senderID);
        break;

      case 'typing off':
        sendTypingOff(senderID);
        break;

      case 'account linking':
        sendAccountLinking(senderID);
        break;

      default:
        // sendTextMessage(senderID, messageText);
        sendToWatson(senderID, messageText);
    }
  } else if (messageAttachments) {
    sendTextMessage(senderID, "Message with attachment received");
  }
}

let contextStack = {}

function sendToWatson(senderID, userMessage) {
  // sendTypingOn(senderID);

  // Start conversation with empty message.
  conversation.message({
    input: { text: userMessage },
    context: contextStack[senderID]
  }, processResponse);

  // Process the conversation response.
  function processResponse(err, response) {
    if (err) {
      console.error(err); // something went wrong
      sendTextMessage(senderID, err);
      return;
    }

    // If an intent was detected, log it out to the console.
    if (response.intents.length > 0) {
      console.log(colors.green('Detected intent: #' + response.intents[0].intent));
    }
    // If there is a current context, log it out to the console.
    if ( contextStack[senderID] ) {
      console.log(colors.red('Current context ' + JSON.stringify(contextStack[senderID])));
    }

    // Display the output from dialog, if any.
    if (response.output.text.length != 0) {
        console.log(response.output.text[0]);
        sendTextMessage(senderID, response.output.text[0]);
    }

    // Store the context to enable a conversation to happen
    // we are storing a context per senderID to enable
    // multiple conversations to happen with Watson simultaneously
    contextStack[senderID] = response.context;

    // If we detect an action in the response, act on it
    if (response.output.action) {
      console.log(colors.yellow('Detected action: #' + response.output.action));

      let params = '';
      let isSavingsAction = false;
      let endConversation = false;
      switch (response.output.action) {
        case currentAccountActions.insurance:
          params = "?filter[where][type][regexp]=/Current%20Account/i&[filter][where][mobile_insurance]=true&filter[limit]=1";
          isSavingsAction = true;
          break;
        case currentAccountActions.interest:
          params = '?filter[where][type][regexp]=/Current%20Account/i&filter[where][interest%20rate][gt]=1&filter[limit]=1';
          isSavingsAction = true;
          break;
        case currentAccountActions.cashback:
          params = '?filter[where][type][regexp]=/Current%20Account/i&filter[where][cashback]=true&filter[limit]=1';
          isSavingsAction = true;
          break;
        case 'check_balance':
          // sendTextMessage(senderID, 'Your current account balance is £1756.78');
          sendBankBalanceTemplateMessage(senderID);
          break;
        case 'end_conversation':
          endConversation = true;
          break;
        default:
          // Do nothing
          break;
      }
      if (isSavingsAction) {
        let account = getBankingOffers(params).then(function(result) {
          sendGenericMessage(senderID, result[0]);
        });
      }
      // if we got an action to end the conversation
      if (endConversation) {
        // delete the context for this conversation
        delete contextStack[senderID];
      }
    }
  }
}

function sendBankBalanceTemplateMessage(recipientId) {

  var template = {
    recipient: {
      id: recipientId
    },
    message: {
      attachment: {
        type: 'template',
        payload: {
          template_type: 'list',
          top_element_style: 'large',
          elements: [
            {
              title: "All your accounts: HSBC, NatWest, Lloyds",
              image_url: SERVER_URL + '/assets/watson.png',
              subtitle: "Your total balance is £5210.44",
              default_action: {
                type: "web_url",
                url: "https://facebook.com/chattybank",
                messenger_extensions: false,
                webview_height_ratio: "tall",
                fallback_url: "https://hsbc.com"
              }
            },
            {
              title: "HSBC Current Account",
              image_url: SERVER_URL + '/assets/banks/hsbc.jpg',
              subtitle: "Your HSBC balance is £1902.89",
              default_action: {
                type: "web_url",
                url: "https://hsbc.com",
                messenger_extensions: false,
                webview_height_ratio: "tall",
                fallback_url: "https://hsbc.com"
              },
              buttons: [
                {
                  type: "web_url",
                  url: "https://hsbc.com",
                  title: "Go to HSBC's website"
                }
              ]
            },
            {
              title: "NatWest Savings Account",
              image_url: SERVER_URL + '/assets/banks/natwest.png',
              subtitle: "Your NatWest balance is £1348.89",
              default_action: {
                type: "web_url",
                url: "https://natwest.com",
                messenger_extensions: false,
                webview_height_ratio: "tall",
                fallback_url: "https://natwest.com"
              },
              buttons: [
                {
                  type: "web_url",
                  url: "https://natwest.com",
                  title: "Go to NatWest's website"
                }
              ]
            },
            {
              title: "Lloyds Joint Current Account",
              image_url: SERVER_URL + '/assets/banks/lloyds.jpg',
              subtitle: "Your NatWest balance is £1958.66",
              default_action: {
                type: "web_url",
                url: "https://www.lloydsbank.com/",
                messenger_extensions: false,
                webview_height_ratio: "tall",
                fallback_url: "https://www.lloydsbank.com/"
              },
              buttons: [
                {
                  type: "web_url",
                  url: "https://www.lloydsbank.com/",
                  title: "Go to Lloyds' website"
                }
              ]
            }
          ]
        }
      }
    }
  }

  callSendAPI(template);
}

function sendTemplateMessage(recipientId, account) {

  var template = {
    recipient: {
      id: recipientId
    },
    message: {
      attachment: {
        type: 'template',
        payload: {
          template_type: 'generic',
          elements: [
            {
              title: account.name,
              image_url: account.img_url,
              subtitle: account.description,
              default_action: {
                type: "web_url",
                url: account.product_website,
                messenger_extensions: false,
                webview_height_ratio: "tall",
                fallback_url: account.product_website
              },
              buttons: [
                {
                  type: "web_url",
                  url: account.product_website,
                  title: "Go to " + account.brand + "'s website"
                }
              ]
            }
          ]
        }
      }
    }
  }

  callSendAPI(template);
}

function getBankingOffers(params) {
  const https = require('https');
  const host = 'api.eu.apiconnect.ibmcloud.com';
  const path = '/matthewcroninukibmcom-mattcronin/development/api/products';
  return new Promise(function( resolve, reject ) {
    https.get({
      host: host,
      path: path + params,
      headers: {
        'X-IBM-Client-ID': API_KEY,
        'X-IBM-Client-Secret': API_SECRET
      }
    }, (res) => {
      console.log(res.statusCode);
      res.on("data", function(chunk) {
        resolve(JSON.parse(chunk.toString()));
      });
    })
  })
}

/*
 * Delivery Confirmation Event
 *
 * This event is sent to confirm the delivery of a message. Read more about
 * these fields at https://developers.facebook.com/docs/messenger-platform/webhook-reference/message-delivered
 *
 */
function receivedDeliveryConfirmation(event) {
  var senderID = event.sender.id;
  var recipientID = event.recipient.id;
  var delivery = event.delivery;
  var messageIDs = delivery.mids;
  var watermark = delivery.watermark;
  var sequenceNumber = delivery.seq;

  if (messageIDs) {
    messageIDs.forEach(function(messageID) {
      console.log("Received delivery confirmation for message ID: %s",
        messageID);
    });
  }

  console.log("All message before %d were delivered.", watermark);
}


/*
 * Postback Event
 *
 * This event is called when a postback is tapped on a Structured Message.
 * https://developers.facebook.com/docs/messenger-platform/webhook-reference/postback-received
 *
 */
function receivedPostback(event) {
  var senderID = event.sender.id;
  var recipientID = event.recipient.id;
  var timeOfPostback = event.timestamp;

  // The 'payload' param is a developer-defined field which is set in a postback
  // button for Structured Messages.
  var payload = event.postback.payload;

  console.log("Received postback for user %d and page %d with payload '%s' " +
    "at %d", senderID, recipientID, payload, timeOfPostback);

  // When a postback is called, we'll send a message back to the sender to
  // let them know it was successful
  sendTextMessage(senderID, "Postback called");
}

/*
 * Message Read Event
 *
 * This event is called when a previously-sent message has been read.
 * https://developers.facebook.com/docs/messenger-platform/webhook-reference/message-read
 *
 */
function receivedMessageRead(event) {
  var senderID = event.sender.id;
  var recipientID = event.recipient.id;

  // All messages before watermark (a timestamp) or sequence have been seen.
  var watermark = event.read.watermark;
  var sequenceNumber = event.read.seq;

  console.log("Received message read event for watermark %d and sequence " +
    "number %d", watermark, sequenceNumber);
}

/*
 * Account Link Event
 *
 * This event is called when the Link Account or UnLink Account action has been
 * tapped.
 * https://developers.facebook.com/docs/messenger-platform/webhook-reference/account-linking
 *
 */
function receivedAccountLink(event) {
  var senderID = event.sender.id;
  var recipientID = event.recipient.id;

  var status = event.account_linking.status;
  var authCode = event.account_linking.authorization_code;

  console.log("Received account link event with for user %d with status %s " +
    "and auth code %s ", senderID, status, authCode);
}


/*
 * Send a text message using the Send API.
 *
 */
function sendTextMessage(recipientId, messageText) {
  var messageData = {
    recipient: {
      id: recipientId
    },
    message: {
      text: messageText,
      metadata: "DEVELOPER_DEFINED_METADATA"
    }
  };

  callSendAPI(messageData);
}

/*
 * Send a Structured Message (Generic Message type) using the Send API.
 *
 */
function sendGenericMessage(recipientId, account) {
  var messageData = {
    recipient: {
      id: recipientId
    },
    message: {
      attachment: {
        type: "template",
        payload: {
          template_type: "generic",
          elements: [{
            title: account.name,
            subtitle: account.description,
            item_url: account.product_website,
            image_url: account.img_url,
            buttons: [{
              type: "web_url",
              url: account.product_website,
              title: `Open ${account.brand}'s website`
            }, {
              type: "postback",
              title: `Call ${account.brand}`,
              payload: `Call ${account.brand}`,
            }],
          }]
        }
      }
    }
  };

  callSendAPI(messageData);
}

/*
 * Call the Send API. The message data goes in the body. If successful, we'll
 * get the message id in a response
 *
 */
function callSendAPI(messageData) {
  request({
    uri: 'https://graph.facebook.com/v2.6/me/messages',
    qs: { access_token: PAGE_ACCESS_TOKEN },
    method: 'POST',
    json: messageData

  }, function (error, response, body) {
    if (!error && response.statusCode == 200) {
      var recipientId = body.recipient_id;
      var messageId = body.message_id;

      if (messageId) {
        console.log("Successfully sent message with id %s to recipient %s",
          messageId, recipientId);
      } else {
      console.log("Successfully called Send API for recipient %s",
        recipientId);
      }
    } else {
      console.error("Failed calling Send API", response.statusCode, response.statusMessage, body.error);
    }
  });
}

// Start server
// Webhooks must be available via SSL with a certificate signed by a valid
// certificate authority.
app.listen(app.get('port'), function() {
  console.log('Node app is running on port', app.get('port'));
});

module.exports = app;
