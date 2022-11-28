import { ReactElement, useEffect, useState } from "react"
import { cacheAnswer, getQuestion, sendAnswers } from "./Services/QuestionServices"
import './index.css'
import { Button } from 'react-bootstrap'
import { getCacheAnswers } from "../LoginPage/Service/userService";
import { useNavigate } from "react-router-dom";

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

interface ResponseQuestion {
    id: string;
    question: string;
    answers: string[];
    answered: string
}
export const HomePage = (): ReactElement => {
    let navigate = useNavigate()
    const userName = localStorage.getItem('userName')
    const [active, setActive] = useState(false);
    const [questions, setQuestions] = useState<Question[]>([]);
    const [score, setScore] = useState();
    const getListQuestion = async () => {
        const listQuestion: Question[] = await getQuestion()
        let listAnswers: ListAnswers = {answers: []}
        const list: ResponseQuestion[] = await getCacheAnswers(userName)
        if(list.length !== 0){
            for(let i = 0; i < list.length; i++){
                if(list[i].answered !== ''){
                    listAnswers.answers.push({id: list[i].id, answer: list[i].answered})
                }
            }
        }
        setListAnswereds(listAnswers);
        setQuestions(listQuestion)
        setActive(true)
    }

    const [listAnswereds, setListAnswereds] = useState<ListAnswers>({ answers: [] })

    const handleChooseAnswer = async (ans: string, id: string) => {
        let listAnswers = JSON.parse(JSON.stringify(listAnswereds))
        for (let i = 0; i < listAnswers.answers.length; i++) {
            if (id == listAnswers.answers[i].id) {
                listAnswers.answers[i].answer = ans
                setListAnswereds(listAnswers)
                return;
            }
        }
        listAnswers.answers.push({ id: id, answer: ans })
        console.log(listAnswers)
        setListAnswereds(listAnswers)
    }

    const handleSubmit = async () => {
        const resScore = await sendAnswers(listAnswereds)
        setScore(resScore)
    }

    const handleSave = async () => {
        const saveAnswer = await cacheAnswer(userName, listAnswereds)
        console.log(saveAnswer)
        navigate('/')
    }
    return (
        <div>
            <Button onClick={getListQuestion}>Lấy câu hỏi</Button>
            {active ? <>
                <div className="quiz-form">
                    {questions.map((val) => {
                        return (
                            <div >
                                <div>{val.id}. {val.question}</div>
                                <div>{listAnswereds.answers.filter((ans) => ans.id == val.id)[0]?.answer ? listAnswereds.answers.filter((ans) => ans.id == val.id)[0].answer : "None"}</div>
                                <Button className="answer-button" onClick={() => { handleChooseAnswer(val.answers[0], val.id) }}>A.{val.answers[0]}</Button>

                                <Button className="answer-button" onClick={() => { handleChooseAnswer(val.answers[1], val.id) }}>B.{val.answers[1]}</Button>

                                <Button className="answer-button" onClick={() => { handleChooseAnswer(val.answers[2], val.id) }}>C.{val.answers[2]}</Button>

                                <Button className="answer-button" onClick={() => { handleChooseAnswer(val.answers[3], val.id) }}>D.{val.answers[3]}</Button>
                            </div>
                        )
                    })}
                    <Button onClick={handleSave}>Lưu và thoát</Button>
                    <Button onClick={handleSubmit}>Nộp</Button>
                </div></> : null}

        </div>
    )
}
