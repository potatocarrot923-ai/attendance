export default async function handler(req, res) {
  if (req.method !== "POST") {
    return res.status(405).json({
      success: false,
      message: "Method not allowed"
    });
  }

  try {
    const { phone } = req.body || {};

    if (!phone) {
      return res.status(400).json({
        success: false,
        message: "Phone number is required"
      });
    }

    // Normalize Philippine numbers
    let normalizedPhone = String(phone).replace(/[\s()-]/g, "");

    if (normalizedPhone.startsWith("09")) {
      normalizedPhone = "63" + normalizedPhone.substring(1);
    } else if (normalizedPhone.startsWith("+63")) {
      normalizedPhone = normalizedPhone.substring(1);
    }

    if (!/^639\d{9}$/.test(normalizedPhone)) {
      return res.status(400).json({
        success: false,
        message: "Invalid Philippine mobile number"
      });
    }

    // Generate 6-digit OTP
    const otp = Math.floor(100000 + Math.random() * 900000).toString();

    /*
      Send the OTP through Semaphore's dedicated OTP endpoint.
      The API key NEVER appears in this GitHub code.
    */
    const smsResponse = await fetch(
      "https://api.semaphore.co/api/v4/otp",
      {
        method: "POST",
        headers: {
          "Content-Type": "application/x-www-form-urlencoded"
        },
        body: new URLSearchParams({
          apikey: process.env.SEMAPHORE_API_KEY,
          number: normalizedPhone,
          message: "Your password reset code is {otp}. It expires in 5 minutes.",
          code: otp
        })
      }
    );

    const smsResult = await smsResponse.json();

    if (!smsResponse.ok) {
      console.error("Semaphore error:", smsResult);

      return res.status(502).json({
        success: false,
        message: "SMS provider failed to send the OTP"
      });
    }

    /*
      Store OTP in Upstash Redis.

      IMPORTANT:
      We store the OTP using the server-side Redis credentials.
      The browser never receives the OTP.
    */

    const redisKey = `password-reset:${normalizedPhone}`;

    const redisResponse = await fetch(
      `${process.env.UPSTASH_REDIS_REST_URL}/set/${encodeURIComponent(redisKey)}/${otp}/EX/300`,
      {
        method: "POST",
        headers: {
          Authorization: `Bearer ${process.env.UPSTASH_REDIS_REST_TOKEN}`
        }
      }
    );

    const redisResult = await redisResponse.json();

    if (!redisResponse.ok || redisResult.result !== "OK") {
      console.error("Redis error:", redisResult);

      return res.status(500).json({
        success: false,
        message: "Could not save OTP"
      });
    }

    return res.status(200).json({
      success: true,
      message: "OTP sent successfully"
    });

  } catch (error) {
    console.error("Forgot password error:", error);

    return res.status(500).json({
      success: false,
      message: "Server error"
    });
  }
}
