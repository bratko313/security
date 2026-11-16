
const loginForm = document.getElementById("loginForm");
const recordForm = document.getElementById("recordForm");

const currentUser = document.getElementById("currentUser");
const loginMessage = document.getElementById("loginMessage");
const recordResult = document.getElementById("recordResult");
const logoutButton = document.getElementById("logoutButton");

// Provjera trenutne sjednice
async function refreshSession() {
    const response = await fetch("/me", {
        credentials: "same-origin",
        cache: "no-store"
    });

    const data = await response.json();

    currentUser.textContent = data.authenticated
        ? data.username
        : "Nitko";

    logoutButton.disabled = !data.authenticated;
}

// Prijava korisnika
loginForm.addEventListener("submit", async (event) => {
    event.preventDefault();

    const formData = new FormData(loginForm);

    try {
        const response = await fetch("/login", {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            credentials: "same-origin",
            body: JSON.stringify({
                username: formData.get("username"),
                password: formData.get("password")
            })
        });

        const data = await response.json();

        loginMessage.textContent =
            `HTTP ${response.status}: ${data.message}`;

        if (response.ok) {
            loginForm.reset();
            recordResult.textContent =
                "Prijava uspješna. Odaberite zapis.";
        }

        await refreshSession();
    } catch (error) {
        loginMessage.textContent =
            "Pogreška pri komunikaciji s poslužiteljem.";
        console.error(error);
    }
});

// Odjava korisnika
logoutButton.addEventListener("click", async () => {
    try {
        await fetch("/logout", {
            method: "POST",
            credentials: "same-origin"
        });

        loginMessage.textContent = "Korisnik je odjavljen.";
        recordResult.textContent = "Nema aktivnog zahtjeva.";

        await refreshSession();
    } catch (error) {
        loginMessage.textContent = "Odjava nije uspjela.";
        console.error(error);
    }
});

// Dohvaćanje zapisa - demonstracija IDOR-a
recordForm.addEventListener("submit", async (event) => {
    event.preventDefault();

    const params = new URLSearchParams(
        new FormData(recordForm)
    );

    const url = `/records?${params.toString()}`;

    try {
        const response = await fetch(url, {
            credentials: "same-origin",
            cache: "no-store"
        });

        const data = await response.json();

        const lines = [
            `Zahtjev: GET ${url}`,
            `HTTP status: ${response.status}`,
            `Poruka: ${data.message}`
        ];

        if (data.check) {
            lines.push(data.check);
        }

        if (data.record) {
            lines.push(
                "",
                `ID: ${data.record.id}`,
                `Vlasnik: ${data.record.owner}`,
                `Naslov: ${data.record.title}`,
                `Sadržaj: ${data.record.content}`
            );
        }

        recordResult.textContent = lines.join("\n");
    } catch (error) {
        recordResult.textContent =
            "Pogreška pri dohvaćanju zapisa.";
        console.error(error);
    }
});

// Inicijalna provjera sjednice
refreshSession().catch(console.error);
