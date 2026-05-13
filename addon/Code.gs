// ============================================================
// Gmail Add-on: Malicious Email Scorer
// Replace BACKEND_URL with your ngrok URL when running locally
// ============================================================

var BACKEND_URL = "https://YOUR_NGROK_URL";  // e.g. https://abc123.ngrok.io
var BACKEND_API_KEY = ""; // Optional: set to match backend BACKEND_API_KEY

// ------------------------------------------------------------
// Entry point: called when the user opens an email
// ------------------------------------------------------------
function onGmailMessage(e) {
  var accessToken = e.gmail.accessToken;
  var messageId   = e.gmail.messageId;

  GmailApp.setCurrentMessageAccessToken(accessToken);
  var message = GmailApp.getMessageById(messageId);

  // --- Collect email data ---
  var fromHeader = message.getFrom();           // "Name <email@domain.com>"
  var fromEmail  = extractEmail(fromHeader);
  var fromName   = extractName(fromHeader);
  var subject    = message.getSubject();
  var body       = message.getPlainBody();
  var rawHeaders = getRawHeaders(message);
  var urls       = extractUrls(body);

  // --- Call backend ---
  var payload = {
    message_id: messageId,
    from_email:  fromEmail,
    from_name:   fromName,
    subject:     subject,
    body:        body.substring(0, 5000),   // limit body size
    headers:     rawHeaders,
    urls:        urls
  };

  var result = callBackend("/scan", "POST", payload);

  if (!result) {
    return buildErrorCard("Could not reach the scoring backend. Is it running?");
  }

  return buildResultCard(result, fromEmail);
}

// ------------------------------------------------------------
// Card: main result view
// ------------------------------------------------------------
function buildResultCard(result, fromEmail) {
  var card = CardService.newCardBuilder();
  card.setHeader(
    CardService.newCardHeader()
      .setTitle("Email Risk Score")
      .setSubtitle(result.verdict)
      .setImageUrl(verdictIcon(result.verdict))
  );

  // --- Score section ---
  var scoreSection = CardService.newCardSection();
  scoreSection.addWidget(
    CardService.newTextParagraph().setText(
      "<b>" + result.total_score + " / 100</b>  —  <font color='" + verdictColor(result.verdict) + "'>" + result.verdict + "</font>"
    )
  );
  scoreSection.addWidget(
    CardService.newTextParagraph().setText("<i>Scanned at: " + result.scanned_at + "</i>")
  );
  card.addSection(scoreSection);

  // --- Signals section ---
  var signalSection = CardService.newCardSection().setHeader("Contributing Signals");
  result.signals.forEach(function(signal) {
    var icon  = signal.passed ? "✅" : "❌";
    var label = icon + "  <b>" + signal.name + "</b>  (" + signal.score + ")";
    signalSection.addWidget(
      CardService.newDecoratedText()
        .setTopLabel(signal.name)
        .setText(signal.detail)
        .setWrapText(true)
    );
  });
  card.addSection(signalSection);

  // --- Actions section ---
  var actionsSection = CardService.newCardSection().setHeader("Actions");

  // Block/unblock sender
  var blockAction = CardService.newAction()
    .setFunctionName("blockSender")
    .setParameters({ email: fromEmail });

  actionsSection.addWidget(
    CardService.newTextButton()
      .setText("🚫 Block This Sender")
      .setOnClickAction(blockAction)
  );

  // View history
  var historyAction = CardService.newAction()
    .setFunctionName("showHistory");

  actionsSection.addWidget(
    CardService.newTextButton()
      .setText("📋 View Scan History")
      .setOnClickAction(historyAction)
  );

  card.addSection(actionsSection);
  return card.build();
}

// ------------------------------------------------------------
// Card: scan history
// ------------------------------------------------------------
function showHistory() {
  var history = callBackend("/history", "GET", null);
  var card = CardService.newCardBuilder();
  card.setHeader(CardService.newCardHeader().setTitle("Recent Scans"));

  var section = CardService.newCardSection();

  if (!history || history.length === 0) {
    section.addWidget(CardService.newTextParagraph().setText("No scans yet."));
  } else {
    history.slice(0, 10).forEach(function(item) {
      section.addWidget(
        CardService.newDecoratedText()
          .setTopLabel(item.verdict + "  —  " + item.total_score + "/100")
          .setText(item.from_email + "\n" + item.subject)
          .setWrapText(true)
      );
    });
  }

  card.addSection(section);
  return CardService.newActionResponseBuilder()
    .setNavigation(CardService.newNavigation().pushCard(card.build()))
    .build();
}

// ------------------------------------------------------------
// Block sender
// ------------------------------------------------------------
function blockSender(e) {
  var email = e.parameters.email;
  callBackend("/blocklist/" + encodeURIComponent(email), "POST", null);

  return CardService.newActionResponseBuilder()
    .setNotification(CardService.newNotification().setText("🚫 " + email + " blocked."))
    .build();
}

// ------------------------------------------------------------
// Error card
// ------------------------------------------------------------
function buildErrorCard(message) {
  var card = CardService.newCardBuilder();
  card.setHeader(CardService.newCardHeader().setTitle("⚠️ Error"));
  var section = CardService.newCardSection();
  section.addWidget(CardService.newTextParagraph().setText(message));
  card.addSection(section);
  return card.build();
}

// ------------------------------------------------------------
// Helpers
// ------------------------------------------------------------
function callBackend(path, method, body) {
  try {
    var options = {
      method: method.toLowerCase(),
      contentType: "application/json",
      muteHttpExceptions: true,
      headers: {}
    };
    if (BACKEND_API_KEY) options.headers["X-API-Key"] = BACKEND_API_KEY;
    if (body) options.payload = JSON.stringify(body);

    var response = UrlFetchApp.fetch(BACKEND_URL + path, options);
    if (response.getResponseCode() === 200) {
      return JSON.parse(response.getContentText());
    }
    return null;
  } catch (err) {
    Logger.log("Backend error: " + err.message);
    return null;
  }
}

function extractEmail(from) {
  var match = from.match(/<(.+?)>/);
  return match ? match[1] : from.trim();
}

function extractName(from) {
  var match = from.match(/^(.+?)\s*</);
  return match ? match[1].trim().replace(/^"|"$/g, "") : "";
}

function extractUrls(text) {
  var urlRegex = /https?:\/\/[^\s"'<>]+/g;
  var matches = text.match(urlRegex) || [];
  // Deduplicate
  return matches.filter(function(v, i, a) { return a.indexOf(v) === i; });
}

function getRawHeaders(message) {
  // Apps Script doesn't expose raw headers directly.
  // We pull what we can from the message object.
  var headers = {};
  try {
    headers["from"] = message.getFrom();
    headers["to"]   = message.getTo();
    headers["date"] = message.getDate().toString();
    // SPF/DKIM/DMARC headers require Gmail API (advanced service)
    // They will be empty unless the advanced Gmail API is enabled.
  } catch (e) {}
  return headers;
}

function verdictColor(verdict) {
  if (verdict === "MALICIOUS")  return "#d32f2f";
  if (verdict === "SUSPICIOUS") return "#f57c00";
  return "#388e3c";
}

function verdictIcon(verdict) {
  if (verdict === "MALICIOUS")  return "https://fonts.gstatic.com/s/i/googlematerialicons/dangerous/v14/24px.svg";
  if (verdict === "SUSPICIOUS") return "https://fonts.gstatic.com/s/i/googlematerialicons/warning/v14/24px.svg";
  return "https://fonts.gstatic.com/s/i/googlematerialicons/check_circle/v14/24px.svg";
}
