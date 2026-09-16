export default async function handler(req, res) {
  if (req.method !== "POST") {
    return res.status(405).json({
      success: false,
      message: "Method not allowed"
    });
  }

  try {
    const {
      phone,
      otp,
      newPassword
    } = req.body || {};

    if (!phone || !otp || !newPassword) {
      return res.status(400).json({
        success: false,
        message: "Phone, OTP, and new password are required"
      });
    }

    if (!/^\d{6}$/.test(String(otp))) {
      return res.status(400).json({
        success: false,
        message: "OTP must contain 6 digits"
      });
    }

    if (String(newPassword).length < 8) {
      return res.status(400).json({
        success: false,
        message: "Password must be at least 8 characters"
      });
    }

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

    const redisKey = `password-reset:${normalizedPhone}`;

    // Get the OTP stored by forgot-password.js
    const redisResponse = await fetch(
      `${process.env.UPSTASH_REDIS_REST_URL}/get/${encodeURIComponent(redisKey)}`,
      {
        headers: {
          Authorization: `Bearer ${process.env.UPSTASH_REDIS_REST_TOKEN}`
        }
      }
    );

    const redisResult = await redisResponse.json();

    if (!redisResponse.ok) {
      return res.status(500).json({
        success: false,
        message: "Could not verify OTP"
      });
    }

    const storedOtp = redisResult.result;

    if (!storedOtp) {
      return res.status(400).json({
        success: false,
        message: "OTP expired or not found"
      });
    }

    if (String(storedOtp) !== String(otp)) {
      return res.status(400).json({
        success: false,
        message: "Incorrect OTP"
      });
    }

    /*
      OTP is correct.

      IMPORTANT:
      This is where your actual instructor-user database
      must update the password.

      Do NOT simply store passwords in GitHub/localStorage.
      Your existing user database/authentication system
      needs to be connected here.
    */

    // Delete the OTP so it cannot be reused.
    await fetch(
      `${process.env.UPSTASH_REDIS_REST_URL}/del/${encodeURIComponent(redisKey)}`,
      {
        method: "POST",
        headers: {
          Authorization: `Bearer ${process.env.UPSTASH_REDIS_REST_TOKEN}`
        }
      }
    );

    return res.status(200).json({
      success: true,
      message: "OTP verified successfully"
    });

  } catch (error) {
    console.error("Verify reset error:", error);

    return res.status(500).json({
      success: false,
      message: "Server error"
    });
  }
}
