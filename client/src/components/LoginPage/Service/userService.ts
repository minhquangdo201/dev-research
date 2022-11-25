import axios from "axios";
interface User {
    userName: string;
    password: string;
}

interface ListAnswers {
    answers: Answer[]
}

interface Answer {
    id?: string;
    answer?: string;
}


export const creatAccount = async (user: User): Promise<any> => {
    axios.post('http://localhost:8000/user/postUser', {
        userName: user.userName,
        password: user.password
    })
        .then(function (response) {
            return response.data
        })
        .catch(function (error) {
            console.log(error);
        });
}

export const login = async ({userName, password}: {userName: string, password: string}): Promise<any> => {
    return axios.post('http://localhost:8000/user/login', {
        userName: userName,
        password: password,
    })
        .then(function (response) {
            console.log(response.data);
            return response.data;
        })
        .catch(function (error) {
            console.log(error);
        });
}

export const getCacheAnswers = async(userName: any): Promise<ListAnswers> => {
    const url = 'http://localhost:8000/getCacheAnswers'
    try {
        const res = await axios.post(url, {userName: userName})
        console.log(res.data)
        return res.data
    } catch(error: any) {
        return error
    }
}