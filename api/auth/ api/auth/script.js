App.requestResetCode = async function () {
  const phoneInput = document.getElementById("resetPhone");
  const notice = document.getElementById("resetNotice");

  const phone = phoneInput.value.trim();

  if (!phone) {
    notice.textContent = "Please enter your recovery phone number.";
    return;
  }

  const normalizedPhone = phone.replace(/[\s()-]/g, "");

  const validPH =
    /^09\d{9}$/.test(normalizedPhone) ||
    /^\+639\d{9}$/.test(normalizedPhone);

  if (!validPH) {
    notice.textContent = "Enter a valid Philippine mobile number.";
    return;
  }

  notice.textContent = "Sending OTP...";

  try {
    const response = await fetch("/api/auth/forgot-password", {
      method: "POST",
      headers: {
        "Content-Type": "application/json"
      },
      body: JSON.stringify({
        phone: normalizedPhone
      })
    });

    const result = await response.json();

    if (!response.ok || !result.success) {
      notice.textContent =
        result.message || "Unable to send OTP.";
      return;
    }

    notice.textContent = "OTP sent. Check your phone.";

    document
      .getElementById("resetStep1")
      .classList.add("hidden");

    document
      .getElementById("resetStep2")
      .classList.remove("hidden");

  } catch (error) {
    console.error(error);
    notice.textContent = "Could not connect to the server.";
  }
};


App.submitPasswordReset = async function () {
  const phone =
    document.getElementById("resetPhone").value.trim();

  const otp =
    document.getElementById("smsCodeInput").value.trim();

  const newPassword =
    document.getElementById("newPasswordInput").value;

  const notice =
    document.getElementById("resetNotice");

  if (!/^\d{6}$/.test(otp)) {
    notice.textContent = "Enter the 6-digit OTP.";
    return;
  }

  if (newPassword.length < 8) {
    notice.textContent =
      "Password must be at least 8 characters.";
    return;
  }

  notice.textContent = "Verifying OTP...";

  try {
    const response = await fetch("/api/auth/verify-reset", {
      method: "POST",
      headers: {
        "Content-Type": "application/json"
      },
      body: JSON.stringify({
        phone: phone,
        otp: otp,
        newPassword: newPassword
      })
    });

    const result = await response.json();

    if (!response.ok || !result.success) {
      notice.textContent =
        result.message || "OTP verification failed.";
      return;
    }

    notice.textContent =
      "OTP verified successfully.";

  } catch (error) {
    console.error(error);
    notice.textContent =
      "Could not connect to the server.";
  }
};
