package com.example.instazoo.web;

import com.example.instazoo.dto.CommentDTO;
import com.example.instazoo.entity.Comment;
import com.example.instazoo.entity.Post;
import com.example.instazoo.facade.CommentFacade;
import com.example.instazoo.payload.response.MessageResponse;
import com.example.instazoo.services.CommentService;
import com.example.instazoo.validations.ResponseErrorValidation;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.util.ObjectUtils;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.*;

import java.security.Principal;
import java.util.List;
import java.util.stream.Collectors;

@RestController
@RequestMapping("api/comment")
@CrossOrigin
public class CommentController {
    @Autowired
    private  CommentFacade commentFacade;
    @Autowired
    private  CommentService commentService;
    @Autowired
    private ResponseErrorValidation responseErrorValidation;

    @PostMapping("/{postId}/create")
    public ResponseEntity<Object> createComment(@Valid @RequestBody CommentDTO commentDTO,
                                                @PathVariable("postId") String postId, BindingResult bindingResult, Principal principal){
        ResponseEntity<Object> errors = responseErrorValidation.mapValidationService(bindingResult);
        if(!ObjectUtils.isEmpty(errors))return errors;
        Comment comment = commentService.saveComment(Long.parseLong(postId),commentDTO,principal);
        CommentDTO createdComment = commentFacade.commentToCommentDTO(comment);
        return new ResponseEntity<>(createdComment, HttpStatus.CREATED);
    }
    @GetMapping("/{postId}/all")
    public ResponseEntity<List<CommentDTO>> getAllCommentsToPost(@PathVariable("postId") String postId){
        List<CommentDTO> commentDTOS = commentService.getAllCommentsForPost(Long.parseLong(postId)).stream()
                .map(commentFacade::commentToCommentDTO)
                .collect(Collectors.toList());
        return new ResponseEntity<>(commentDTOS,HttpStatus.OK);
    }
    @PostMapping("/{commentId}/delete")
    public ResponseEntity<MessageResponse>deleteComment(@PathVariable("commentId")String commentId){
        commentService.deleteComment(Long.parseLong(commentId));
        return new ResponseEntity<>(new MessageResponse("Post was deleted"),HttpStatus.OK);
    }
}
