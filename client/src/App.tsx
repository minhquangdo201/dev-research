import './App.css';
import LoginPage from './components/LoginPage/LoginPage';
import { ToastContainer } from 'react-toastify';
import { HomePage } from './components/Home/Home';
import { Routes, Route } from 'react-router-dom'
import { createContext, useState } from 'react';



const App = () => {
  const [user, setUser] = useState('')
  return (

    <Routes>
      <Route path='/' element={<LoginPage />} />
      <Route path='/home' element={<HomePage />} />
    </Routes>

  );
}

export default App;
