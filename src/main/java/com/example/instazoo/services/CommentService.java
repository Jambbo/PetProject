package com.example.instazoo.services;

import com.example.instazoo.dto.CommentDTO;
import com.example.instazoo.entity.Comment;
import com.example.instazoo.entity.Post;
import com.example.instazoo.entity.User;
import com.example.instazoo.exceptions.PostNotFoundException;
import com.example.instazoo.repository.CommentRepository;
import com.example.instazoo.repository.PostRepository;
import com.example.instazoo.repository.UserRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.security.Principal;
import java.security.cert.CertPath;
import java.util.List;
import java.util.Optional;

@Service
public class CommentService {
    public static final Logger LOG = LoggerFactory.getLogger(CommentService.class);

    private final CommentRepository commentRepository;
    private final PostRepository postRepository;
    private final UserRepository userRepository;
    @Autowired
    public CommentService(CommentRepository commentRepository, PostRepository postRepository, UserRepository userRepository) {
        this.commentRepository = commentRepository;
        this.postRepository = postRepository;
        this.userRepository = userRepository;
    }

    public Comment saveComment(Long postId, CommentDTO commentDTO, Principal principal){
        User user = getUserByPrincipal(principal);
        Post post = postRepository.findById(postId).orElseThrow(() -> new PostNotFoundException("Post cannot be found for username: "+user.getEmail()));
        Comment comment = new Comment();
        comment.setPost(post);
        comment.setUserId(user.getId());
        comment.setMessage(commentDTO.getMessage());
        comment.setUsername(commentDTO.getUsername());
        LOG.info("Saving comment for Post: {}",post.getId());
        return commentRepository.save(comment);
    }
    public List<Comment> getAllCommentsForPost(Long postId){
        Post post = postRepository.findById(postId).orElseThrow(() -> new PostNotFoundException("Post cannot be found"));
        return commentRepository.findAllByPost(post);
    }

    public void deleteComment(Long commentId){
        Optional<Comment> comment = commentRepository.findById(commentId);
        comment.ifPresent(commentRepository::delete);
    }

    private User getUserByPrincipal(Principal principal) {
        String username = principal.getName();
        return userRepository.findUserByUsername(username).orElseThrow(
                () -> new UsernameNotFoundException("Username not found with username " + username)
        );
    }

}
