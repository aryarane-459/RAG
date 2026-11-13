const API_BASE = (window.location.hostname === "localhost")
    ? "http://localhost:8000"
    : "http://127.0.0.1:8000";

const loginForm = document.getElementById("loginForm");
const emailInput = document.getElementById("email");
const passwordInput = document.getElementById("password");
const loginButton = document.getElementById("loginButton");
const formMessage = document.getElementById("formMessage");

const otpForm = document.getElementById("otpForm");
const otpInput = document.getElementById("otp");

const togglePassword = document.getElementById("togglePassword");
const profileButton = document.getElementById("profileButton");
const profileMenu = document.getElementById("profileMenu");

togglePassword.addEventListener("click", () => {
    const passwordIsHidden = passwordInput.type === "password";

    passwordInput.type = passwordIsHidden ? "text" : "password";
    togglePassword.textContent = passwordIsHidden ? "Hide" : "Show";
    togglePassword.setAttribute(
        "aria-label",
        passwordIsHidden ? "Hide password" : "Show password"
    );
});

profileButton.addEventListener("click", () => {
    const isHidden = profileMenu.hidden;

    profileMenu.hidden = !isHidden;
    profileButton.setAttribute("aria-expanded", String(isHidden));
});

document.getElementById("profileLogin").addEventListener("click", () => {
    profileMenu.hidden = true;
    emailInput.focus();
});


let currentUserRole = null;


document.querySelectorAll(".nav-item").forEach((button) => {

    button.addEventListener("click", () => {

        if (!currentUserRole) {
            formMessage.textContent = "Please sign in first.";
            return;
        }

        const page = button.dataset.page;

        // Admin-only pages
        if (
            ["assign-role", "user-logins", "databases"].includes(page) &&
            currentUserRole !== "admin"
        ) {
            formMessage.textContent = "Admin access required.";
            return;
        }

        // Highlight selected sidebar item
        document.querySelectorAll(".nav-item").forEach(item => {
            item.classList.remove("active");
        });

        button.classList.add("active");

        // Hide other sections
        document.querySelector(".landing-layout").style.display = "none";
        document.getElementById("workspaceSection").style.display = "none";
        document.getElementById("adminSection").style.display = "none";

        // Hide all admin pages
        document.querySelectorAll(".admin-page").forEach(section => {
            section.style.display = "none";
        });

        if (page === "create-user") {

            document.getElementById("workspaceSection").style.display = "block";

        } else {

            document.getElementById("adminSection").style.display = "block";

            if (page === "databases") {
                document.getElementById("databasesPage").style.display = "block";
            }

            if (page === "assign-role") {
                document.getElementById("assignRolePage").style.display = "block";
            }

            if (page === "user-logins") {
                document.getElementById("createUsersPage").style.display = "block";
            }
        }
    });
});



loginForm.addEventListener("submit", async (event) => {
    event.preventDefault();

    formMessage.textContent = "";
    loginButton.disabled = true;
    loginButton.querySelector("span").textContent = "Signing in...";

    try {
        const response = await fetch(
            "http://127.0.0.1:8000/auth/login",
            {
                method: "POST",
                headers: {
                    "Content-Type": "application/json"
                },
                credentials: "include",
                body: JSON.stringify({
                    email: emailInput.value.trim(),
                    password: passwordInput.value
                })
            }
        );

        const result = await response.json();

        if (!response.ok) {
            throw new Error(
                result.detail || "Login failed. Please check your credentials."
            );
        }

        if (!result.otp_required) {
            throw new Error("The server did not request OTP verification.");
        }

        formMessage.style.color = "#169c6b";
        formMessage.textContent =
            result.message || "OTP sent to your registered email.";

        loginForm.style.display = "none";
        otpForm.style.display = "block";
        otpInput.focus();

    } catch (error) {
        formMessage.style.color = "#d43e51";
        formMessage.textContent =
            error.message || "Unable to connect to the server.";
    } finally {
        loginButton.disabled = false;
        loginButton.querySelector("span").textContent =
            "Sign in to your account";
    }
});

otpForm.addEventListener("submit", async (event) => {
    event.preventDefault();

    const verifyButton = document.getElementById("verifyOtpButton");
    const otp = otpInput.value.trim();

    if (!/^\d{6}$/.test(otp)) {
        formMessage.style.color = "#d43e51";
        formMessage.textContent = "Please enter a valid 6-digit OTP.";
        return;
    }

    verifyButton.disabled = true;
    verifyButton.querySelector("span").textContent = "Verifying...";
    formMessage.textContent = "";

    try {
        const response = await fetch(
            "http://127.0.0.1:8000/auth/verify-otp",
            {
                method: "POST",
                headers: {
                    "Content-Type": "application/json"
                },
                credentials: "include",
                body: JSON.stringify({
                    email: emailInput.value.trim(),
                    otp: otp
                })
            }
        );

        const result = await response.json();

        if (!response.ok) {
            throw new Error(
                result.detail || "OTP verification failed."
            );
        }

        formMessage.style.color = "#169c6b";
        formMessage.textContent =
            "Email verified. You are now logged in successfully.";

        otpForm.style.display = "none";
        await checkLoginSession();

    
    } catch (error) {
        formMessage.style.color = "#d43e51";
        formMessage.textContent =
            error.message || "Unable to verify OTP.";
    } finally {
        verifyButton.disabled = false;
        verifyButton.querySelector("span").textContent = "Verify OTP";
    }
});

document.getElementById("forgotPassword").addEventListener("click", () => {
    formMessage.style.color = "#3568e8";
    formMessage.textContent =
        "Password reset will be available after email OTP is configured.";
});

function showWorkspace() {
    document.querySelector(".landing-layout").style.display = "none";

    document.getElementById("workspaceSection").style.display = "block";

    document.getElementById("adminSection").style.display = "none";
}


async function loadAccessibleDatabases() {

    const selector = document.getElementById("databaseSelector");

    if (!selector) {
        console.error("[DocuMind] databaseSelector element not found in HTML.");
        return;
    }

    selector.innerHTML = '<option value="">Loading databases...</option>';

    try {
        const response = await fetch(
            `${API_BASE}/databases/accessible`,
            {
                method: "GET",
                credentials: "include"
            }
        );

        console.log("[DocuMind] Database API status:", response.status);

        const result = await response.json();

        console.log("[DocuMind] Database API response:", result);

        if (!response.ok) {
            throw new Error(result.detail || "Unable to fetch databases");
        }

        selector.innerHTML = '<option value="">Select a database</option>';

        if (!Array.isArray(result.databases)) {
            console.error("[DocuMind] Expected databases array, received:", result);
            selector.innerHTML = '<option value="">Unable to load databases</option>';
            return;
        }

        if (result.databases.length === 0) {
            selector.innerHTML = '<option value="">No databases available</option>';
            return;
        }

        result.databases.forEach(database => {

            const option = document.createElement("option");

            option.value = database.database_id;
            option.textContent = database.db_name || database.database_name;

            selector.appendChild(option);

        });

    } catch (error) {

        console.error("[DocuMind] Database loading error:", error);

        selector.innerHTML =
            '<option value="">Unable to load databases</option>';
    }
}


async function checkLoginSession() {

    try {

        const response = await fetch(
            `${API_BASE}/auth/me`,
            {
                method: "GET",
                credentials: "include"
            }
        );

        if (!response.ok) {
            currentUserRole = null;

            document.querySelector(".landing-layout").style.display = "grid";
            document.getElementById("workspaceSection").style.display = "none";
            document.getElementById("adminSection").style.display = "none";

            loginForm.style.display = "block";
            otpForm.style.display = "none";

            return;
        }

        const result = await response.json();

        currentUserRole = result.role || result.user?.role || null;

        loginForm.style.display = "none";
        otpForm.style.display = "none";

        document.querySelector(".landing-layout").style.display = "none";

        showWorkspace();

        await loadAccessibleDatabases();

        document.querySelectorAll(
            '[data-page="assign-role"], [data-page="user-logins"], [data-page="databases"]'
        ).forEach(button => {
            button.style.display =
                currentUserRole === "admin" ? "flex" : "none";
        });

        document.querySelectorAll(".nav-item").forEach(item => {
            item.classList.remove("active");
        });

        document.querySelector('[data-page="create-user"]')
            .classList.add("active");

    } catch (error) {

        console.error("Session check failed:", error);

    }
    
}

checkLoginSession();


const uploadForm = document.getElementById("uploadForm");

if (uploadForm) {
    uploadForm.addEventListener("submit", async function (event) {
        event.preventDefault();

        const fileInput = document.getElementById("pdfFiles");
        const uploadMessage = document.getElementById("uploadMessage");
        const uploadResults = document.getElementById("uploadResults");
        const uploadButton = document.getElementById("uploadButton");

        const files = Array.from(fileInput.files);

        if (files.length === 0) {
            uploadMessage.textContent = "Please select at least one PDF.";
            return;
        }

        const invalidFiles = files.filter(
            file => !file.name.toLowerCase().endsWith(".pdf")
        );

        if (invalidFiles.length > 0) {
            uploadMessage.textContent = "Please select PDF files only.";
            return;
        }

        const formData = new FormData();

        files.forEach(file => {
            formData.append("files", file);
        });

        uploadButton.disabled = true;
        uploadMessage.textContent = "Uploading and processing PDFs...";
        uploadResults.replaceChildren();

        try {
            const response = await fetch(
                "http://127.0.0.1:8000/upload",
                {
                    method: "POST",
                    credentials: "include",
                    body: formData
                }
            );

            const result = await response.json();

            if (!response.ok) {
                throw new Error(
                    result.detail || "Unable to upload the PDFs."
                );
            }

            uploadMessage.textContent =
                result.message || "Upload request completed.";

            if (Array.isArray(result.files)) {
                result.files.forEach(file => {
                    const item = document.createElement("p");

                    const filename = document.createElement("strong");
                    filename.textContent = file.filename || "PDF document";

                    const status = document.createElement("span");
                    status.textContent = file.status === "processed"
                        ? " — Uploaded and processed successfully"
                        : file.status === "processing_failed"
                            ? " — Uploaded, but processing failed"
                            : " — Uploaded";

                    item.append(filename, status);
                    uploadResults.appendChild(item);
                });
            } else {
                uploadMessage.textContent =
                    "PDF upload completed successfully.";
            }

            fileInput.value = "";

        } catch (error) {
            uploadMessage.textContent = error.message;
        } finally {
            uploadButton.disabled = false;
        }
    });
}


const askForm = document.getElementById("askForm");
const questionInput = document.getElementById("questionInput");
const askButton = document.getElementById("askButton");
const askMessage = document.getElementById("askMessage");
const answerBox = document.getElementById("answerBox");
const answerText = document.getElementById("answerText");
const sqlDetails = document.getElementById("sqlDetails");
const sqlText = document.getElementById("sqlText");


askForm.addEventListener("submit", async (event) => {
    event.preventDefault();

    const question = questionInput.value.trim();

    if (!question) {
        askMessage.style.color = "#b91c1c";
        askMessage.textContent = "Please enter a question.";
        return;
    }

    const selectedDatabaseId = document.getElementById("databaseSelector").value;

    if (!selectedDatabaseId) {
        askMessage.style.color = "#b91c1c";
        askMessage.textContent = "Please select a database.";
        return;
    }

    const payload = {
        question: question,
        database_id: selectedDatabaseId
    };

    askButton.disabled = true;
    askButton.textContent = "Processing...";
    askMessage.style.color = "#3568e8";
    askMessage.textContent = "Analyzing question and generating SQL...";
    answerBox.style.display = "none";
    if (sqlDetails) {
        sqlDetails.style.display = "none";
        sqlDetails.removeAttribute("open");
    }

    // Progressive status updates for better user feedback
    const progressTimers = [
        setTimeout(() => {
            if (askButton.disabled) {
                askMessage.textContent = "Executing database query...";
            }
        }, 2500),
        setTimeout(() => {
            if (askButton.disabled) {
                askMessage.textContent = "Generating natural language answer...";
            }
        }, 5000)
    ];

    try {
        const response = await fetch(`${API_BASE}/ask-database`, {
            method: "POST",
            credentials: "include",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify(payload)
        });

        const result = await response.json();

        if (!response.ok) {
            throw new Error(
                result.detail || result.message || "Could not answer your question."
            );
        }

        answerText.textContent = result.answer;

        if (result.sql_query && sqlDetails && sqlText) {
            sqlText.textContent = result.sql_query;
            sqlDetails.style.display = "block";
        }

        answerBox.style.display = "block";
        askMessage.style.color = "#15803d";
        askMessage.textContent = "Answer generated successfully.";

    } catch (error) {
        console.error("Question request failed:", error);
        askMessage.style.color = "#b91c1c";
        askMessage.textContent = error.message || "Something went wrong.";
    } finally {
        progressTimers.forEach(timer => clearTimeout(timer));
        askButton.disabled = false;
        askButton.textContent = "Ask Question";
    }
});


const databaseForm = document.getElementById("databaseForm");
if (databaseForm) {
    databaseForm.addEventListener("submit", async (event) => {
        event.preventDefault();

        const databaseName = document.getElementById("databaseName").value.trim();
        const databaseHost = document.getElementById("databaseHost").value.trim();
        const databasePort = parseInt(document.getElementById("databasePort").value, 10) || 5432;
        const databaseDbName = document.getElementById("databaseDbName").value.trim();
        const databaseUsername = document.getElementById("databaseUsername").value.trim();
        const databasePassword = document.getElementById("databasePassword").value;
        const submitBtn = document.getElementById("testSaveDatabase");
        const messageEl = document.getElementById("databaseMessage");

        messageEl.style.color = "#3568e8";
        messageEl.textContent = "Testing connection and saving database...";
        submitBtn.disabled = true;

        const payload = {
            database_name: databaseName,
            db_type: "postgresql",
            host: databaseHost,
            port: databasePort,
            db_name: databaseDbName,
            username: databaseUsername,
            password: databasePassword,
            assigned_user_ids: []
        };

        try {
            const response = await fetch(`${API_BASE}/admin/databases`, {
                method: "POST",
                headers: {
                    "Content-Type": "application/json"
                },
                credentials: "include",
                body: JSON.stringify(payload)
            });

            const result = await response.json();

            if (!response.ok) {
                throw new Error(result.detail || "Failed to register database.");
            }

            messageEl.style.color = "#169c6b";
            messageEl.textContent = result.message || "Database tested and registered successfully!";
            databaseForm.reset();
            const portInput = document.getElementById("databasePort");
            if (portInput) portInput.value = "5432";

            // Refresh the database dropdown so the newly registered DB appears immediately
            await loadAccessibleDatabases();

        } catch (error) {
            console.error("Database registration error:", error);
            messageEl.style.color = "#d43e51";
            messageEl.textContent = error.message || "Failed to register database.";
        } finally {
            submitBtn.disabled = false;
        }
    });
}
