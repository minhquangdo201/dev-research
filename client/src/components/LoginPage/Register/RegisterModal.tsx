import { ReactElement, useState } from 'react';
import Button from 'react-bootstrap/Button';
import Modal from 'react-bootstrap/Modal';
import Form from 'react-bootstrap/Form';
import { ToastContainer, toast } from 'react-toastify';
interface User {
    userName: string;
    password: string;
}

interface RegisterProps {
    save: (user: User) => Promise<void>
}
const RegisterModal = (props: RegisterProps): ReactElement => {
    const [show, setShow] = useState(false);
    const [user, setUser] = useState<User>({ userName: '', password: '' });
    const handleClose = () => setShow(false);
    const handleShow = () => setShow(true);
    const handleSave = () => {
        if (user.userName === '' || user.password === '') {
            toast.error('Vui lòng không để trống!', {
                position: toast.POSITION.TOP_RIGHT
            });
        } else {
            props.save(user);
            toast.success('Đăng ký thành công !')
            setShow(false);
        }
    }
    return (
        <div>
            <Button variant="primary" onClick={handleShow}>
                Đăng ký
            </Button>

            <Modal show={show} onHide={handleClose}>
                <Modal.Header closeButton>
                    <Modal.Title>Đăng ký</Modal.Title>
                </Modal.Header>
                <Modal.Body>
                    <Form>
                        <div>
                            <label htmlFor="">Tài khoản</label>
                            <input
                                type='text'
                                required={true}
                                value={user.userName} onChange={(e) => setUser({ ...user, userName: e.target.value })} />
                        </div>
                        <div>
                            <label htmlFor="">Mật khẩu</label>
                            <input
                                type='password'
                                required={true}
                                value={user.password} onChange={(e) => setUser({ ...user, password: e.target.value })} />
                        </div>
                    </Form>
                </Modal.Body>
                <Modal.Footer>
                    <Button variant="secondary" onClick={handleClose}>
                        Hủy
                    </Button>
                    <Button variant="primary" onClick={handleSave}>
                        Đăng ký
                    </Button>
                </Modal.Footer>
            </Modal>
        </div>
    );
}

export default RegisterModal;