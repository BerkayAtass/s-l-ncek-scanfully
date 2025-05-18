import {
  BrowserRouter,
  Routes,
  Route,
} from "react-router-dom";
import { createRoot } from 'react-dom/client'
import './index.css'
import App from './App.jsx'
import Login from "./pages/login.jsx";
import Scan from "./pages/scan.jsx"
import OldScan from "./pages/oldScan.jsx"
import { Provider } from "react-redux";
import {store} from "./redux/store.jsx"
import ScanDetail from "./pages/scanDetail.jsx";

createRoot(document.getElementById('root')).render(
  <Provider store={store}>

    <BrowserRouter>
    
      <Routes>
        <Route path="/" element={<Scan/>}/>
        {/* <Route path="/login" element={<Login/>}/> */}
        {/* <Route path="/login" element={<Login/>}/> */}
        <Route path="/scan" element={<Scan/>}/>
        <Route path="/oldScan" element={<OldScan/>}/>
        <Route path="/scanDetails/:id" element={<ScanDetail/>}/>
      </Routes>

      <App />
      
    </BrowserRouter>
  </Provider>


)
