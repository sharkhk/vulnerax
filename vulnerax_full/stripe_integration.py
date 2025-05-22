import os
import stripe
from flask import Blueprint, jsonify, request, current_app

stripe.api_key = os.getenv("STRIPE_SECRET_KEY")
stripe_bp = Blueprint("stripe_bp", __name__)

@stripe_bp.route("/create-checkout-session", methods=["POST"])
def create_checkout_session():
    data = request.get_json()
    try:
        session = stripe.checkout.Session.create(
            mode="subscription",
            payment_method_types=["card"],
            line_items=[{"price": os.getenv("STRIPE_PRICE_ID"), "quantity": 1}],
            success_url=data["success_url"] + "?session_id={CHECKOUT_SESSION_ID}",
            cancel_url=data["cancel_url"],
        )
        return jsonify({"sessionId": session.id})
    except Exception as e:
        current_app.logger.error("Stripe session error: %s", e)
        return jsonify(error=str(e)), 400

@stripe_bp.route("/stripe-webhook", methods=["POST"])
def stripe_webhook():
    payload = request.data
    sig_header = request.headers.get("Stripe-Signature", "")
    endpoint_secret = os.getenv("STRIPE_WEBHOOK_SECRET")
    try:
        event = stripe.Webhook.construct_event(payload, sig_header, endpoint_secret)
    except stripe.error.SignatureVerificationError:
        current_app.logger.error("Stripe signature error")
        return "Invalid signature", 400

    if event["type"] == "checkout.session.completed":
        session = event["data"]["object"]
        current_app.logger.info("Stripe checkout completed: %s", session.id)
    return "", 200
