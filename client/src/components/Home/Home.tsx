import { ReactElement, useState } from "react"
import { getQuestion, sendAnswers } from "./Services/QuestionServices"
import './index.css'
import { Button } from 'react-bootstrap'
import { idText } from "typescript";

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

export const HomePage = (): ReactElement => {
    const [active, setActive] = useState(false);
    const [questions, setQuestions] = useState<Question[]>([]);
    const [score, setScore] = useState();
    const getListQuestion = async () => {
        const listQuestion: Question[] = await getQuestion()
        setQuestions(listQuestion)
        setActive(true)
    }
    const listAnswers: ListAnswers = {answers: []}
    const handleChooseAnswer = (ans: string, id: string) => {
        for(let i = 0; i < listAnswers.answers.length; i++){
            if(id == listAnswers.answers[i].id){
                listAnswers.answers[i].answer = ans
                return;
            }

        }
        listAnswers.answers.push({id: id, answer:ans})

    }

    const handleSubmit = async () => {
        const resScore = await sendAnswers(listAnswers)
        console.log(resScore)
        setScore(resScore)
    }

    return (
        <div>
            <Button onClick={getListQuestion}>Lấy câu hỏi</Button>
            {active ? <>
                <div className="quiz-form">
                    {questions.map((val, key) => {

                        return (
                            <div >
                                <div>{val.id}. {val.question}</div>
                                
                                <Button className="answer-button" onClick={() => { handleChooseAnswer(val.answers[0], val.id) }}>A.{val.answers[0]}</Button>
                                
                                <Button className="answer-button" onClick={() => { handleChooseAnswer(val.answers[1], val.id)}}>B.{val.answers[1]}</Button>
                                
                                <Button className="answer-button" onClick={() => { handleChooseAnswer(val.answers[2], val.id)}}>C.{val.answers[2]}</Button>
                            
                                <Button className="answer-button" onClick={() => { handleChooseAnswer(val.answers[3], val.id)}}>D.{val.answers[3]}</Button>
                            </div>
                        )
                    })}
                    {score ? <div>{score}</div> : <Button onClick={handleSubmit}>Nộp</Button>}
                </div></> : null}
        </div>
    )
}
