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
    let score = 0
    const [selected, setSelected] = useState('')
    
    const [active, setActive] = useState(false);
    const [questions, setQuestions] = useState<Question[]>([]);
    const getListQuestion = async () => {
        const listQuestion: Question[] = await getQuestion()
        setQuestions(listQuestion)
        setActive(true)
    }

    const correct = ['', '', '', '', '', '', '', '', '', '']

    const handleChooseAnswer = (ans: string, correctAns: string, id: any) => {
        console.log(id - 1)
        if (ans === correctAns) {
            correct.splice(id - 1, 1, ans)
            console.log('click')
            console.log(correct)
        }
        if (ans !== correctAns) {
            correct.splice(id - 1, 1, '')
            console.log(correct)
        }

    }
    const handleChooseAnswer2 = (ans: string, correctAns: string, id: any, e: any) => {
        console.log(id - 1)
        if (ans === correctAns) {
            correct.splice(id - 1, 1, ans)
            console.log('click')
            console.log(correct)
        }
        if (ans !== correctAns) {
            correct.splice(id - 1, 1, '')
            console.log(correct)
        }
        setSelected(e.currentTarget)

    }
    const getScore = () => {
        for (let i = 0; i < correct.length; i++) {
            if (correct[i] !== '') {
                score++;
            }
        }
    }
    const handleSubmit = (e: any) => {
        getScore()
        e.currentTarget.disabled = true;
        console.log(score)
    }

    return (
        <div>
            <Button onClick={getListQuestion}>Lấy câu hỏi</Button>
            {active ? <>
                <div className="quiz-form">
                    {questions.map((val, key) => {
                        const isRadioSelected = (value:string):boolean => selected === value
                        return (
                            <div key={key}>
                                <div>{val.id}. {val.question}</div>
                                <input type='radio' value='radio1' checked={isRadioSelected('radio1')} onChange = {(e) => handleChooseAnswer2(val.answers[0], val.correctAns, val.id, e)}/>
                                <Button className="answer-button" onClick={() => { handleChooseAnswer(val.answers[0], val.correctAns, val.id) }}>A.{val.answers[0]}</Button>
                                <input type='radio' value='radio2' checked={isRadioSelected('radio2')} onChange = {(e) => handleChooseAnswer2(val.answers[0], val.correctAns, val.id, e)}/>
                                <Button className="answer-button" onClick={() => { handleChooseAnswer(val.answers[1], val.correctAns, val.id)}}>B.{val.answers[1]}</Button>
                                <input type='radio' value='radio3' checked={isRadioSelected('radio3')} onChange = {(e) => handleChooseAnswer2(val.answers[0], val.correctAns, val.id, e)}/>
                                <Button className="answer-button" onClick={() => { handleChooseAnswer(val.answers[2], val.correctAns, val.id)}}>C.{val.answers[2]}</Button>
                                <input type='radio' value='radio4' checked={isRadioSelected('radio4')} onChange = {(e) => handleChooseAnswer2(val.answers[0], val.correctAns, val.id, e)}/>
                                <Button className="answer-button" onClick={() => { handleChooseAnswer(val.answers[3], val.correctAns, val.id)}}>D.{val.answers[3]}</Button>
                            </div>
                        )
                    })}
                    <Button onClick={(e) => handleSubmit(e)}>Nộp</Button>
                </div></> : null}
        </div>
    )
}
