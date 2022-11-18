export class QuestionInterface {
    id: String;
    question: String;
    answers: String[];
    correctAns?: String;
}

export class ResponseQuestion {
    id: String;
    question: String;
    answers: String[];
}
