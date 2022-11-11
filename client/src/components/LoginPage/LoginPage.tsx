import { useState } from 'react';
import RegisterModal from './Register/RegisterModal';
import './index.css'
import { creatAccount, login } from './Service/userService';
import { toast } from 'react-toastify';

interface User {
    userName: string;
    password: string;
}
const LoginPage = () => {
    const [users, setUsers] = useState<User[]>([])
    const [loginUserName, setLoginUserName] = useState<string>();
    const [loginPassword, setLoginPassword] = useState<string>();
    const handleCreatAccount = async (account: User) => {
        await creatAccount(account);
        const newAccount: User = {
            userName: account.userName,
            password: account.password,
        }
        setUsers([newAccount, ...users]);

    }

    const handleLogin = async (e: any) => {
        e.preventDefault();
        console.log(loginUserName)
        console.log(loginPassword)
        if(!loginUserName || !loginPassword){
            toast.error('Vui lòng nhập đầy đủ !')
            return;
        }
        const success = await login({userName: loginUserName, password: loginPassword});
        console.log(success)
        if(success){
            toast.success('Đăng nhập thành công!')
        } else {
            toast.error('Tài khoản hoặc mật khẩu không đúng!')
        }
    }
    return (
        <div className='login-form-outer'>
            <form onSubmit={(e) => handleLogin(e)}>
                <h2>Đăng nhập</h2>
                <div className="login-input">
                    <label htmlFor="">Tài khoản</label>
                    <input
                        type='text'
                        value={loginUserName}
                        onChange={(e) => setLoginUserName(e.target.value)}
                    />
                </div>
                <div className="login-input">
                    <label htmlFor="">Mật khẩu</label>
                    <input
                        type='password'
                        value={loginPassword}
                        onChange={(e) => setLoginPassword(e.target.value)}
                    />
                </div>
                <button>Đăng nhập</button>
                <RegisterModal save={handleCreatAccount} />
            </form>
        </div>
    )
}

export default LoginPage;