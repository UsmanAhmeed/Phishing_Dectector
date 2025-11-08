// --- Phishing Email Analyzer ---
const analyzeBtn = document.getElementById("analyzeBtn");
const clearBtn = document.getElementById("clearBtn");
const emailText = document.getElementById("emailText");

// DOM Elements for Results
const resultsContainer = document.getElementById("results");
const verdictEl = document.getElementById("verdict");
const scoreEl = document.getElementById("score");
const reasonsEl = document.getElementById("reasons");
const detailsPre = document.getElementById("details");

analyzeBtn.addEventListener("click", () => {
    const email = emailText.value.trim();
    if (!email) {
        alert("Please paste an email to analyze.");
        return;
    }

    // Temporarily disable button and show loading state (optional)
    analyzeBtn.textContent = "Analyzing...";
    analyzeBtn.disabled = true;

    fetch("/analyze", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email: email })
    })
    .then(response => response.json())
    .then(data => {
        analyzeBtn.textContent = "Analyze Email";
        analyzeBtn.disabled = false;
        
        if (data.error) {
            alert(data.error);
            return;
        }

        // Show results container
        resultsContainer.classList.remove("hidden");

        // Determine styling based on score/verdict
        const score = data.score || 0;
        const isHighRisk = score >= 50; // Using 50 as the risk threshold
        const verdictColorClass = isHighRisk ? "text-red-600" : "text-green-600";

        // Verdict
        verdictEl.textContent = data.verdict || "Analysis Complete";
        // Apply the correct color class from the Tailwind structure
        verdictEl.className = `font-extrabold text-xl ${verdictColorClass}`;

        // Score
        scoreEl.textContent = `${score} / 100`;
        scoreEl.className = `font-bold text-lg ${verdictColorClass}`;


        // Indicators / reasons
        reasonsEl.innerHTML = "";
        const reasonsList = data.reasons || ["No specific indicators found."];
        reasonsList.forEach(r => {
            const li = document.createElement("li");
            li.textContent = r;
            reasonsEl.appendChild(li);
        });

        // Details (pretty JSON, using the dark background style from the HTML)
        detailsPre.textContent = JSON.stringify(data.details, null, 2);
    })
    .catch(err => {
        console.error("Error analyzing email:", err);
        analyzeBtn.textContent = "Analyze Email";
        analyzeBtn.disabled = false;
        alert("A network error occurred during analysis.");
    });
});

// Clear button functionality
clearBtn.addEventListener("click", () => {
    emailText.value = "";
    verdictEl.textContent = "";
    scoreEl.textContent = "";
    reasonsEl.innerHTML = "";
    detailsPre.textContent = "";
    resultsContainer.classList.add("hidden");
});

// ------------------------------------
// --- Chatbot Functionality ---
// ------------------------------------
const chatBox = document.getElementById("chatBox");
const chatInput = document.getElementById("chatInput");
const sendChatBtn = document.getElementById("sendChat");
const chatWindow = document.getElementById("chatWindow");
const chatToggleBtn = document.getElementById("chatToggle");
const chatCloseBtn = document.getElementById("chatClose");

// Append chat message function (Updated for better Tailwind styling)
function appendChatMessage(sender, text) {
    const msg = document.createElement("div");
    
    // Set styles based on sender to match the new structure
    let classes = ["p-2", "rounded-xl", "max-w-[85%]", "break-words", "text-sm", "shadow-md"];
    if (sender === "user") {
        // bg-primary-blue is defined as #1e40af
        classes.push("bg-primary-blue", "text-white", "self-end");
    } else {
        classes.push("bg-gray-100", "text-gray-800", "self-start");
    }

    msg.classList.add(...classes);
    msg.textContent = text;
    chatBox.appendChild(msg);
    chatBox.scrollTop = chatBox.scrollHeight; // auto-scroll
}

// Send chat message
async function sendChatMessage() {
    const text = chatInput.value.trim();
    if (!text) return;

    appendChatMessage("user", text);
    chatInput.value = "";

    // 1. Show loading message
    const loadingMsg = document.createElement("div");
    loadingMsg.id = 'loading-msg';
    loadingMsg.classList.add("bg-gray-100", "text-gray-600", "p-2", "rounded-xl", "max-w-[85%]", "self-start", "text-sm", "shadow-sm");
    loadingMsg.textContent = "Assistant is typing...";
    chatBox.appendChild(loadingMsg);
    chatBox.scrollTop = chatBox.scrollHeight;

    try {
        const response = await fetch("/chat", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ message: text })
        });
        
        // 2. Remove loading message before showing result
        document.getElementById('loading-msg')?.remove();

        const data = await response.json();
        appendChatMessage("bot", data.reply || "Error: Could not get a response from the security assistant.");
    } catch (err) {
        console.error(err);
        // 2. Remove loading message before showing error
        document.getElementById('loading-msg')?.remove();
        appendChatMessage("bot", "Error connecting to chatbot. Please check the network.");
    }
}

// Event listeners for sending messages
sendChatBtn.addEventListener("click", sendChatMessage);
chatInput.addEventListener("keypress", e => {
    if (e.key === "Enter") {
        e.preventDefault();
        sendChatMessage();
    }
});

// --- Chat window toggle ---
chatToggleBtn.addEventListener("click", () => {
    chatWindow.classList.toggle("hidden");
});

chatCloseBtn.addEventListener("click", () => {
    chatWindow.classList.add("hidden");
});
