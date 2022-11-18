import { ReactElement, useState } from "react"
import { getQuestion } from "./Services/QuestionServices"
import './index.css'
import { Button } from 'react-bootstrap'

interface Question {
    id: string;
    question: string;
    answers: string[];
    correctAns: string;
}

export const HomePage = (): ReactElement => {
    const [active, setActive] = useState(false);
    const [questions, setQuestions] = useState<Question[]>([]);
    const getListQuestion = async () => {
        const listQuestion: Question[] = await getQuestion()
        setQuestions(listQuestion)
        setActive(true)
    }

    const correct = ['', '', '', '', '', '', '', '', '', '']

    const handleChooseAnswer = (ans: string, id: any) => {
        console.log(id - 1)
        correct.splice(id - 1, 1, ans)
        console.log(correct)
    }

    const handleSubmit = (e: any) => {
        e.currentTarget.disabled = true;
    }

    return (
        <div>
            <Button onClick={getListQuestion}>Lấy câu hỏi</Button>
            {active ? <>
                <div className="quiz-form">
                    {questions.map((val, key) => {

                        return (
                            <div key={key}>
                                <div>{val.id}. {val.question}</div>
                                
                                <Button className="answer-button" onClick={() => { handleChooseAnswer(val.answers[0], val.id) }}>A.{val.answers[0]}</Button>
                                
                                <Button className="answer-button" onClick={() => { handleChooseAnswer(val.answers[1], val.id)}}>B.{val.answers[1]}</Button>
                                
                                <Button className="answer-button" onClick={() => { handleChooseAnswer(val.answers[2], val.id)}}>C.{val.answers[2]}</Button>
                            
                                <Button className="answer-button" onClick={() => { handleChooseAnswer(val.answers[3], val.id)}}>D.{val.answers[3]}</Button>
                            </div>
                        )
                    })}
                    <Button onClick={(e) => handleSubmit(e)}>Nộp</Button>
                </div></> : null}
        </div>
    )
}
