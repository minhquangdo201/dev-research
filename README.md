# dev-research

## Yêu cầu
- Environment: Nodejs
- Framework: NestJS
- Database: MongoDB
- Cache: Redis

## Mô tả
Tạo 1 trang web mà người dùng có thể tạo tài khoản và làm bài tập

## Chi tiết
- Người dùng có thể tạo tài khoản với username và password
- Sử dụng username và password đã tạo để đăng nhập
- Sau khi đăng nhập, web hiển thị bộ câu hỏi cùng các lựa chọn A, B, C, D
- Bấm nộp bài sẽ hiển thị điểm số
- Trường hợp người dùng muốn dừng khi đang làm thì có thể bấm nút lưu và thoát

## Hướng dẫn
### Tạo CRUD api
- Viết api đăng ký, đăng nhập
- Viết các api đọc, thêm, sửa, xóa bộ câu hỏi
- Import dữ liệu câu hỏi từ googlesheet

### Tạo api kiểm tra đáp án
- Nhận đầu vào là danh sách đáp án người dùng chọn, trả về điểm số tương ứng

### Xử lí khi người dùng muốn lưu tiến trình hiện tại
- Sử dụng redis(list), set /username
- Khi người dùng đăng nhập lại, get /username để lấy bộ 
