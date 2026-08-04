const storeForOwns = document.querySelector(".owns").outerHTML;
            // Global functions for buttons
            // `them` is the username span
            function userOwns(them, domain) {
                // console.log(them, domain);
                let owns = document.querySelector(".owns");
                let theirFontSize = window
                    .getComputedStyle(them)
                    .getPropertyValue("font-size");
                owns.style.top = `calc(${them.offsetTop}px - (${theirFontSize} * 1.25))`;
                owns.style.display="block";
                owns.style.left = them.offsetLeft + "px";
                owns.onmouseenter = () => {
                    userOwns(them, domain)
                    // I can't believe that actually worked...
                    // But also what if i change "them" to "owns" so it goes up and up
                    // nvm it dont work like that
                }
                owns.onmouseleave = () => {
                    resetOwns()
                }
                owns.innerHTML = owns.innerHTML.replaceAll(
                    "{{DOMAIN}}",
                    domain,
                );
            }
            function resetOwns() {
                // Inner HTML on purpose btw
                // actually now its outer to reset styling
                document.querySelector(".owns").outerHTML = storeForOwns;
            }
            // Socket Stuff + login check i guess?
            let counter = 0;

            const meRes = await fetch("/me");
            if (meRes.status !== 200) {
                window.location.href = "/login.html";
            }
            const chatTemplateResp = await fetch("/chat-template.html");
            const chatTemplate = await chatTemplateResp.text();
            const socket = io({
                auth: {
                    serverOffset: 0,
                },
                ackTimeout: 10000,
                retries: 3,
            });

            const form = document.getElementById("messagebox");
            const input = document.getElementById("message");
            const messages = document.getElementById("messages");
            form.addEventListener("submit", (e) => {
                e.preventDefault();
                if (input.value) {
                    const clientOffset = `${socket.id}-${counter++}`;
                    socket.emit("chat", input.value, clientOffset);
                    input.value = "";
                }
            });
            socket.on("delete", function (offset) {
                // just as a double-check in the db
                let msg = document.getElementById(offset);
                if (msg) msg.remove();
            });

            socket.on("chat", (msg, serverOffset, userData, sentAt) => {
                const item = document.createElement("li");
                const content = document.createElement("div");
                content.classList.add("content");
                // time.classList.add("timestamp");
                item.addEventListener("contextmenu", function (e) {
                    e.preventDefault();
                    socket.emit("delete", serverOffset);
                });
                // user.textContent = username + ": ";
                // message.textContent = msg;
                // time.textContent = sentAt ? " " + new Date(sentAt).toLocaleString() : "";
                item.id = serverOffset;
                // console.log(userData);
                content.innerHTML = chatTemplate
                    .replace("{{USERNAME}}", userData.username)
                    .replace("{{TIMESTAMP}}", sentAt)
                    .replace("{{MESSAGE}}", msg)
                    .replaceAll("{{DOMAIN}}", userData.domainName);
                // content.appendChild(user);
                // content.appendChild(message);
                // content.appendChild(time);
                // TODO: html encode the username
                item.onmouseenter = () => {
                    userOwns(content.querySelector(".username"), userData.domainName);
                };
                item.onmouseleave = () => {
                    resetOwns();
                };
                // i just had the stupidest idea
                item.appendChild(content);
                messages.appendChild(item);
                // onmouseenter="userOwns(this,'{{DOMAIN}}')" onmouseleave="resetOwns()"
                
                window.scrollTo(0, document.body.scrollHeight);
                socket.auth.serverOffset = serverOffset;
            });