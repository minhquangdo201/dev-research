import axios from "axios";

interface Question {
    id: string;
    question: string;
    answers: string[];
    correctAns: string;
}

export const getQuestion = async (): Promise<Question[]> => {
    const url = 'http://localhost:8000/question/getAll';
    try {
        const res = await axios.get(url)
        const question:Question[] = res.data
        console.log(question)
        return question;
    } catch(error: any) {
        return error.response.data.message
    }
}