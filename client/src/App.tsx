import React, { useState } from 'react';
import './App.css';
import axios from 'axios';
import LoginPage from './components/LoginPage/LoginPage';
import { ToastContainer, toast } from 'react-toastify';

const App = () => {
  

  return (
    <div className="App">
      <LoginPage/>
      <ToastContainer/>
    </div>
  );
}

export default App;
