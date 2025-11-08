// --- Phishing Email Analyzer ---
const analyzeBtn = document.getElementById("analyzeBtn");
const clearBtn = document.getElementById("clearBtn");

analyzeBtn.addEventListener("click", () => {
    const email = document.getElementById("emailText").value.trim();
    if (!email) {
        alert("Please paste an email to analyze.");
        return;
    }

    fetch("/analyze", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email: email })
    })
    .then(response => response.json())
    .then(data => {
        if (data.error) {
            alert(data.error);
            return;
        }

        // Show results container
        const resultsContainer = document.getElementById("results");
        resultsContainer.classList.remove("hidden");

        // Verdict
        const verdictEl = document.getElementById("verdict");
        verdictEl.textContent = data.verdict;
        verdictEl.style.color = data.color;

        // Score
        document.getElementById("score").textContent = `Score: ${data.score}`;

        // Indicators / reasons
        const reasonsEl = document.getElementById("reasons");
        reasonsEl.innerHTML = "";
        data.reasons.forEach(r => {
            const li = document.createElement("li");
            li.textContent = r;
            reasonsEl.appendChild(li);
        });

        // Details (JSON pretty)
        document.getElementById("details").textContent = JSON.stringify(data.details, null, 2);
    })
    .catch(err => console.error("Error analyzing email:", err));
});

// Clear button functionality
clearBtn.addEventListener("click", () => {
    document.getElementById("emailText").value = "";
    document.getElementById("verdict").textContent = "";
    document.getElementById("score").textContent = "";
    document.getElementById("reasons").innerHTML = "";
    document.getElementById("details").textContent = "";
    document.getElementById("results").classList.add("hidden");
});

// --- Chatbot Functionality ---
const chatBox = document.getElementById("chatBox");
const chatInput = document.getElementById("chatInput");
const sendChatBtn = document.getElementById("sendChat");

function appendChatMessage(sender, text) {
    const msg = document.createElement("div");
    msg.classList.add("mb-2", sender === "user" ? "text-right" : "text-left");
    msg.innerHTML = `<span class="inline-block px-3 py-1 rounded-lg ${
        sender === "user" ? "bg-blue-500 text-white" : "bg-gray-200 text-gray-800"
    }">${text}</span>`;
    chatBox.appendChild(msg);
    chatBox.scrollTop = chatBox.scrollHeight;
}

async function sendChatMessage() {
    const text = chatInput.value.trim();
    if (!text) return;

    appendChatMessage("user", text);
    chatInput.value = "";

    try {
        const response = await fetch("/chat", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ message: text })
        });
        const data = await response.json();
        if (data.error) {
            appendChatMessage("bot", "Error: " + data.error);
        } else {
            appendChatMessage("bot", data.reply);
        }
    } catch (err) {
        console.error(err);
        appendChatMessage("bot", "Error connecting to chatbot.");
    }
}

sendChatBtn.addEventListener("click", sendChatMessage);
chatInput.addEventListener("keypress", e => {
    if (e.key === "Enter") {
        e.preventDefault();
        sendChatMessage();
    }
});

// --- Floating Chat Toggle Button ---
const chatContainer = document.querySelector(".chat-container");
const chatToggleBtn = document.createElement("button");
chatToggleBtn.textContent = "💬 Chat";
chatToggleBtn.style.position = "fixed";
chatToggleBtn.style.bottom = "20px";
chatToggleBtn.style.right = "20px";
chatToggleBtn.style.backgroundColor = "#1f6feb";
chatToggleBtn.style.color = "#fff";
chatToggleBtn.style.border = "none";
chatToggleBtn.style.borderRadius = "50%";
chatToggleBtn.style.width = "60px";
chatToggleBtn.style.height = "60px";
chatToggleBtn.style.cursor = "pointer";
chatToggleBtn.style.fontSize = "24px";
chatToggleBtn.style.boxShadow = "0 4px 12px rgba(0,0,0,0.2)";
document.body.appendChild(chatToggleBtn);

chatContainer.style.display = "none"; // hidden by default
chatToggleBtn.addEventListener("click", () => {
    chatContainer.style.display =
        chatContainer.style.display === "none" ? "block" : "none";
});
