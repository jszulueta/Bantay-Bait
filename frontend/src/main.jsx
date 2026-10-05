import React from "react"
import ReactDOM from "react-dom/client"
import App from "./App.jsx"
import Admin from "./Admin.jsx"
import "./index.css"

// /admin opens the administrator dashboard; every other path is the public app.
const isAdmin = window.location.pathname.replace(/\/+$/, "") === "/admin"

ReactDOM.createRoot(document.getElementById("root")).render(
  <React.StrictMode>
    {isAdmin ? <Admin /> : <App />}
  </React.StrictMode>,
)
