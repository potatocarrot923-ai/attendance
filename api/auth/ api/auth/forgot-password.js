export default async function handler(req, res) {
  if (req.method !== "POST") {
    return res.status(405).json({
      success: false,
      message: "Method not allowed"
    });
  }

  const { phone } = req.body;

  if (!phone) {
    return res.status(400).json({
      success: false,
      message: "Phone number is required"
    });
  }

  const otp = Math.floor(100000 + Math.random() * 900000).toString();

  try {
    const response = await fetch(
      "https://api.semaphore.co/api/v4/messages",
      {
        method: "POST",
        headers: {
          "Content-Type": "application/json"
        },
        body: JSON.stringify({
          apikey: process.env.SEMAPHORE_API_KEY,
          number: phone,
          message: `Your password reset code is ${otp}. It expires soon.`
        })
      }
    );

    const result = await response.json();

    if (!response.ok) {
      console.error(result);

      return res.status(500).json({
        success: false,
        message: "Failed to send SMS"
      });
    }

    return res.status(200).json({
      success: true,
      message: "OTP sent successfully"
    });

  } catch (error) {
    console.error(error);

    return res.status(500).json({
      success: false,
      message: "SMS service error"
    });
  }
}
