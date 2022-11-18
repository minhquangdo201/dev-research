import axios from "axios";

interface Question {
    id: string;
    question: string;
    answers: string[];
    correctAns: string;
}

interface ListAnswers {
    answers: Answer[]
}

interface Answer {
    id?: string;
    answer?: string;
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

export const sendAnswers = async (answers: ListAnswers): Promise<any> => {
    const url = 'http://localhost:8000/question/getRatio'
    try {
        const res = await axios.post(url,answers)
        return res.data
    } catch(error){
        return error
    }
    // console.log(answers)
    // axios.post('http://localhost:8000/question/getRatio',
    //     answers
    // )
    // .then((res) => {
    //     console.log(res.data)
    //     return res.data
    // })
    // .catch((error) => {
    //     return error;
    // })
}